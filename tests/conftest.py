import json
import zipfile
from contextlib import ExitStack
from functools import partial
from typing import TYPE_CHECKING

import pytest

import osvpy
from explore_toolkit.images import (
    make_fixture,
    make_image,
    registry_resources,
    serve_registry,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path
    from typing import Any


@pytest.fixture
def archive_pair(tmp_path: "Path") -> tuple["Path", "Path"]:
    directory = tmp_path / "imágenes-容器"
    directory.mkdir()
    return make_fixture(directory)


@pytest.fixture
def offline_scan(
    archive_pair: tuple["Path", "Path"],
) -> "Callable[..., osvpy.BatchResult]":
    archive, database = archive_pair
    return partial(
        osvpy.scan_docker_archive, archive, offline=True, database_path=database
    )


@pytest.fixture
def advisory_scan(
    archive_pair: tuple["Path", "Path"],
    offline_scan: "Callable[..., osvpy.BatchResult]",
) -> "Callable[..., osvpy.BatchResult]":
    path = archive_pair[1] / "osv-scalibr/Ubuntu/all.zip"
    with zipfile.ZipFile(path) as archive:
        template = json.loads(archive.read("OSVPY-TEST-0001.json"))

    def scan(*advisories: dict[str, "Any"]) -> osvpy.BatchResult:
        with zipfile.ZipFile(path, "w") as archive:
            for advisory in advisories:
                value = template | advisory
                archive.writestr(f"{value['id']}.json", json.dumps(value))
        return offline_scan()

    return scan


@pytest.fixture
def licensed_archive(tmp_path: "Path") -> "Path":
    return make_image(
        tmp_path,
        {
            "etc/os-release": b"ID=alpine\nVERSION_ID=3.20.0\n",
            "etc/alpine-release": b"3.20.0\n",
            "lib/apk/db/installed": (
                b"P:osvpy-license-allowed\nV:1.0-r0\nA:x86_64\nL:MIT OR Apache-2.0\n\n"
                b"P:osvpy-license-forbidden\nV:1.0-r0\nA:x86_64\nL:GPL-3.0-only\n\n"
            ),
        },
    )


@pytest.fixture
def registry_factory() -> "Iterator[Callable[..., str]]":
    resources = registry_resources()
    with ExitStack() as stack:
        yield lambda **options: stack.enter_context(
            serve_registry(resources, **options)
        )
