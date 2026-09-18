"""A local HTTPS proxy serving independently specified OSV responses."""

import json
import ssl
import subprocess
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

SUMMARY = "Résumé\x00" * 1000
ADVISORY = {
    "id": "OSVPY-EXAMPLE",
    "aliases": ["CVE-2026-12345"],
    "summary": SUMMARY,
    "modified": "2026-01-01T00:00:00.123456789Z",
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    ],
    "references": [{"type": "WEB", "url": "https://example.test/advisory"}],
    "affected": [
        {
            "package": {"name": "example", "ecosystem": "PyPI"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}
            ],
        }
    ],
}


@contextmanager
def advisory_proxy() -> "Iterator[tuple[str, str]]":
    with TemporaryDirectory(prefix="osvpy-tls-") as directory:
        cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "1",
                "-subj",
                "/CN=api.osv.dev",
                "-addext",
                "subjectAltName=DNS:api.osv.dev",
            ],
            check=True,
            capture_output=True,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)

        class Handler(BaseHTTPRequestHandler):
            def do_CONNECT(self) -> None:
                if self.path != "api.osv.dev:443":
                    self.send_error(502)
                    return
                self.send_response(200)
                self.end_headers()
                self.connection = context.wrap_socket(self.connection, server_side=True)
                self.rfile = self.connection.makefile("rb")
                self.wfile = self.connection.makefile("wb")
                self.handle_one_request()

            def respond(self, value: object) -> None:
                body = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path.endswith("/querybatch"):
                    self.respond({
                        "results": [
                            {
                                "vulns": [
                                    {
                                        "id": ADVISORY["id"],
                                        "modified": ADVISORY["modified"],
                                    }
                                ]
                            }
                            if (
                                q.get("package", {}).get("name") == "example"
                                or "pkg:pypi/example@"
                                in q.get("package", {}).get("purl", "")
                            )
                            else {}
                            for q in body["queries"]
                        ]
                    })
                else:
                    self.send_error(404)

            def do_GET(self) -> None:
                if self.path.endswith("/vulns/OSVPY-EXAMPLE"):
                    self.respond(ADVISORY)
                else:
                    self.send_error(404)

            def log_message(self, format: str, *args: object) -> None:
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                yield f"http://127.0.0.1:{server.server_port}", str(cert)
            finally:
                server.shutdown()
                thread.join()
