"""Docker-save images, offline OSV databases, and local multi-platform registries."""

import base64
import gzip
import hashlib
import io
import json
import tarfile
import zipfile
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from pathlib import Path
    from threading import Barrier
    from typing import Any

    from osvpy import RegistryAuth


def _tar(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(content))
    return buffer.getvalue()


def make_image(
    directory: "Path", files: dict[str, bytes], *, architecture: str = "amd64"
) -> "Path":
    """Write a single-image Linux Docker-save archive from filesystem contents."""
    directory.mkdir(parents=True, exist_ok=True)
    layer = _tar(files)
    config = json.dumps({
        "architecture": architecture,
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()],
        },
        "history": [{"created_by": "synthetic osvpy fixture"}],
        "config": {},
    }).encode()
    manifest = json.dumps([
        {
            "Config": "config.json",
            "RepoTags": ["osvpy-fixture:latest"],
            "Layers": ["layer.tar"],
        }
    ]).encode()
    archive = directory / "fixture.tar"
    archive.write_bytes(
        _tar({"manifest.json": manifest, "config.json": config, "layer.tar": layer})
    )
    return archive


def write_database(
    database: "Path", ecosystem: str, advisories: "Iterable[dict[str, Any]]"
) -> "Path":
    """Replace one ecosystem ZIP; do this before starting scans that use it."""
    path = database / "osv-scalibr" / ecosystem / "all.zip"
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as output:
        for advisory in advisories:
            output.writestr(f"{advisory['id']}.json", json.dumps(advisory))
    return path


def make_fixture(
    directory: "Path", *, version: str = "3.0.0-1", details_bytes: int = 0
) -> tuple["Path", "Path"]:
    """Create Ubuntu openssl plus an unaffected package and one local advisory."""
    if details_bytes < 0:
        raise ValueError("details_bytes must be nonnegative")
    archive = make_image(
        directory,
        {
            "etc/os-release": b'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"\n',
            "var/lib/dpkg/status": (
                "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\n"
                f"Version: {version}\nDescription: synthetic osvpy test package\n\n"
                "Package: unaffected\nStatus: install ok installed\nArchitecture: amd64\n"
                "Version: 1.0\nDescription: package without findings\n\n"
            ).encode(),
        },
    )
    database = directory / "db"
    vulnerability = {
        "schema_version": "1.7.0",
        "id": "OSVPY-TEST-0001",
        "modified": "2026-01-01T00:00:00Z",
        "published": "2026-01-01T00:00:00Z",
        "summary": "Synthetic test vulnerability; not a real advisory",
        "details": "x" * details_bytes,
        "affected": [
            {
                "package": {"name": "openssl", "ecosystem": "Ubuntu:24.04"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "3.0.0-2"}],
                    }
                ],
            }
        ],
    }
    write_database(database, "Ubuntu", [vulnerability])
    return archive, database


def registry_resources() -> dict[str, bytes]:
    """Serve an OCI image index containing two architectures, without Docker."""
    # No package inventory: acquisition tests need no external vulnerability service.
    content = _tar({"etc/os-release": b'ID=ubuntu\nVERSION_ID="24.04"\n'})
    config = {
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": ["sha256:" + hashlib.sha256(content).hexdigest()],
        },
        "history": [{"created_by": "registry fixture"}],
    }
    layer = gzip.compress(content, mtime=0)
    resources = {"/v2/": b"{}"}

    def store(content: bytes, kind: str, media_type: str) -> dict[str, object]:
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        resources[f"/v2/fixture/{kind}/{digest}"] = content
        return {"mediaType": media_type, "digest": digest, "size": len(content)}

    blob = store(layer, "blobs", "application/vnd.oci.image.layer.v1.tar+gzip")
    manifests = []
    for architecture in ("amd64", "arm64"):
        configuration = store(
            json.dumps({**config, "architecture": architecture}).encode(),
            "blobs",
            "application/vnd.oci.image.config.v1+json",
        )
        manifest = json.dumps({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": configuration,
            "layers": [blob],
        }).encode()
        descriptor = store(
            manifest, "manifests", "application/vnd.oci.image.manifest.v1+json"
        )
        descriptor["platform"] = {"os": "linux", "architecture": architecture}
        manifests.append(descriptor)
    resources["/v2/fixture/manifests/latest"] = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": manifests,
    }).encode()
    return resources


@contextmanager
def serve_registry(
    resources: dict[str, bytes],
    *,
    auth: "RegistryAuth | None" = None,
    status: int | None = None,
    barrier: "Barrier | None" = None,
) -> "Iterator[str]":
    """A real HTTP registry boundary; the scanner and native loader are unmodified."""
    expected_auth = (
        None
        if auth is None
        else "Basic "
        + base64.b64encode(f"{auth.username}:{auth.password}".encode()).decode()
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if (
                expected_auth is not None
                and self.headers.get("Authorization") != expected_auth
            ):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="fixture"')
                self.end_headers()
                return
            if status is not None:
                self.send_response(status)
                self.end_headers()
                return
            body = resources.get(self.path)
            if body is None:
                self.send_response(404)
                self.end_headers()
                return
            if barrier is not None and self.path == "/v2/fixture/manifests/latest":
                # A single scan cannot release this barrier. Two independent
                # acquisitions must be in flight; a gate fails with a timeout.
                barrier.wait(timeout=15)
            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/octet-stream"
                if "/blobs/" in self.path
                else json.loads(body).get("mediaType", "application/json"),
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"127.0.0.1:{server.server_port}/fixture:latest"
        finally:
            server.shutdown()
            thread.join()
