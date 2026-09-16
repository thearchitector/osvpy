import json
import zipfile
from contextlib import ExitStack
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import pyosv
from tests.fixtures import make_fixture, make_image, registry_resources, serve_registry

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from typing import Any


@pytest.fixture
def recorded_scan() -> dict[str, "Any"]:
    data = json.loads(
        (Path(__file__).parent / "data/complete_response.json").read_text()
    )
    return data


@pytest.fixture
def report(recorded_scan: dict[str, "Any"]) -> pyosv.FullScanResult:
    recorded_scan["result"]["results"].append({
        "source": {"path": "app/requirements.txt", "type": "lockfile"},
        "packages": [
            {
                "package": {
                    "name": "requests",
                    "version": "2.0",
                    "ecosystem": "PyPI",
                    "image_origin_details": {"index": 1},
                },
                "vulnerabilities": [{"id": "SECOND-ADVISORY"}],
            }
        ],
    })
    recorded_scan["result"]["image_metadata"]["layer_metadata"].append({
        "diff_id": "sha256:second",
        "command": "COPY app",
        "is_empty": False,
        "base_image_index": 0,
    })
    return pyosv.FullScanResult.model_validate({
        "image": "ubuntu:latest",
        "metadata": recorded_scan["metadata"],
        **recorded_scan["result"],
    })


@pytest.fixture
def finding_factory(
    report: pyosv.FullScanResult,
) -> "Callable[..., pyosv.Vulnerability]":
    data = report.vulnerabilities[0].model_dump(exclude_computed_fields=True)

    def make(**advisory_fields: object) -> pyosv.Vulnerability:
        return pyosv.Vulnerability.model_validate({
            **data,
            "advisory": {**data["advisory"], **advisory_fields},
        })

    return make


@pytest.fixture
def archive_pair(tmp_path: Path) -> tuple[Path, Path]:
    directory = tmp_path / "imágenes-容器"
    directory.mkdir()
    return make_fixture(directory)


@pytest.fixture
def offline_scan(archive_pair: tuple[Path, Path]) -> "Callable[..., pyosv.ScanResult]":
    archive, database = archive_pair
    return partial(
        pyosv.scan_docker_archive, archive, offline=True, database_path=database
    )


@pytest.fixture
def advisory_scan(
    archive_pair: tuple[Path, Path], offline_scan: "Callable[..., pyosv.ScanResult]"
) -> "Callable[..., pyosv.ScanResult]":
    """Scan the fixture image against explicitly supplied OSV advisories."""
    _, database = archive_pair
    path = database / "osv-scalibr/Ubuntu/all.zip"
    with zipfile.ZipFile(path) as archive:
        template = json.loads(archive.read("PYOSV-TEST-0001.json"))

    def scan(*advisories: dict[str, "Any"]) -> pyosv.ScanResult:
        with zipfile.ZipFile(path, "w") as archive:
            for advisory in advisories:
                value = template | advisory
                archive.writestr(f"{value['id']}.json", json.dumps(value))
        return offline_scan()

    return scan


@pytest.fixture
def licensed_archive(tmp_path: Path) -> Path:
    return make_image(
        tmp_path,
        {
            "etc/os-release": b"ID=alpine\nVERSION_ID=3.20.0\n",
            "etc/alpine-release": b"3.20.0\n",
            "lib/apk/db/installed": (
                b"P:pyosv-license-allowed\nV:1.0-r0\nA:x86_64\nL:MIT OR Apache-2.0\n\n"
                b"P:pyosv-license-forbidden\nV:1.0-r0\nA:x86_64\nL:GPL-3.0-only\n\n"
            ),
        },
    )


@pytest.fixture
def bad_archives(tmp_path: Path) -> dict[str, Path]:
    invalid = tmp_path / "invalid.tar"
    invalid.write_bytes(b"not an image archive")
    return {"missing": tmp_path / "missing.tar", "invalid": invalid}


@pytest.fixture
def registry_factory() -> "Iterator[Callable[..., str]]":
    resources = registry_resources()
    with ExitStack() as stack:
        yield lambda **options: stack.enter_context(
            serve_registry(resources, **options)
        )
