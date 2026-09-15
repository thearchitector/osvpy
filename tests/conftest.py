import json
import os
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from functools import partial
from pathlib import Path
from typing import Any

import pytest

import pyosv
from tests.fixtures import make_fixture, registry_resources, serve_registry


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        for marker, variable in [
            ("integration", "PYOSV_INTEGRATION"),
            ("native", "PYOSV_NATIVE_TESTS"),
        ]:
            if list(item.iter_markers(marker)) and os.environ.get(variable) != "1":
                item.add_marker(pytest.mark.skip(reason=f"Set {variable}=1 to enable"))


@pytest.fixture
def recorded_scan() -> dict[str, Any]:
    data = json.loads(
        (Path(__file__).parent / "data/complete_response.json").read_text()
    )
    return data


@pytest.fixture
def report(recorded_scan: dict[str, Any]) -> pyosv.ScanResult:
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
    return pyosv.ScanResult.model_validate({
        "image": "ubuntu:latest",
        "metadata": recorded_scan["metadata"],
        **recorded_scan["result"],
    })


@pytest.fixture
def finding_factory(report: pyosv.ScanResult) -> Callable[..., pyosv.Vulnerability]:
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
def offline_scan(archive_pair: tuple[Path, Path]) -> Callable[..., pyosv.ScanResult]:
    archive, database = archive_pair
    return partial(
        pyosv.scan_docker_archive, archive, offline=True, database_path=database
    )


@pytest.fixture
def bad_archives(tmp_path: Path) -> dict[str, Path]:
    invalid = tmp_path / "invalid.tar"
    invalid.write_bytes(b"not an image archive")
    return {"missing": tmp_path / "missing.tar", "invalid": invalid}


@pytest.fixture
def registry_factory() -> Iterator[Callable[..., str]]:
    resources = registry_resources()
    with ExitStack() as stack:
        yield lambda **options: stack.enter_context(
            serve_registry(resources, **options)
        )
