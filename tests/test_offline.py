"""An unavailable database is an unknown result, never a clean scan."""

import os
import zipfile
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

import pytest

import osvpy
from explore_toolkit.images import make_fixture, make_image

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize("inventory", [False, True])
@pytest.mark.parametrize("kind", ["missing", "unreadable", "invalid", "directory"])
def test_unavailable_database_slots(
    tmp_path: "Path", inventory: bool, kind: str
) -> None:
    good_dir, bad_dir, empty_dir = [
        tmp_path / name for name in ("good", "bad", "empty")
    ]
    for directory in (good_dir, bad_dir, empty_dir):
        directory.mkdir()
    good, good_db = make_fixture(good_dir)
    bad, bad_db = make_fixture(bad_dir)
    empty = make_image(empty_dir, {"etc/os-release": b"ID=ubuntu\nVERSION_ID=24.04\n"})
    path = bad_db / "osv-scalibr/Ubuntu/all.zip"
    if kind == "missing":
        path.unlink()
    elif kind == "invalid":
        path.write_bytes(b"invalid ZIP")
    elif kind == "directory":
        path.unlink()
        path.mkdir()
    else:
        path.chmod(0)
        if os.access(path, os.R_OK):
            pytest.skip("this user bypasses file permissions")
    try:
        with ThreadPoolExecutor(max_workers=8) as executor:
            bad_futures = [
                executor.submit(
                    osvpy.scan_docker_archive,
                    bad,
                    empty,
                    bad,
                    offline=True,
                    database_path=bad_db,
                    all_packages=inventory,
                )
                for _ in range(4)
            ]
            good_futures = [
                executor.submit(
                    osvpy.scan_docker_archive,
                    good,
                    offline=True,
                    database_path=good_db,
                    all_packages=inventory,
                )
                for _ in range(4)
            ]
            for future in bad_futures:
                batch = future.result(timeout=30)
                assert [im.complete for im in batch.images] == [False, True, False]
                assert [error.code for _, error in batch.errors] == [
                    "offline_unavailable"
                ] * 2
                assert not batch.packages
                assert not batch.findings
                assert batch.images[1].data.metadata.no_packages
            assert all(future.result(timeout=30).complete for future in good_futures)
    finally:
        if kind == "unreadable":
            path.chmod(0o600)


@pytest.mark.parametrize("inventory", [False, True])
def test_multiple_ecosystems_require_every_archive(
    tmp_path: "Path", inventory: bool
) -> None:
    _, database = make_fixture(tmp_path)
    archive = make_image(
        tmp_path,
        {
            "etc/os-release": b"ID=ubuntu\nVERSION_ID=24.04\n",
            "var/lib/dpkg/status": (
                b"Package: openssl\nStatus: install ok installed\nArchitecture: amd64\n"
                b"Version: 3.0.0-1\nDescription: fixture\n\n"
            ),
            "usr/lib/python3/site-packages/example-1.0.dist-info/METADATA": (
                b"Metadata-Version: 2.1\nName: example\nVersion: 1.0\n"
            ),
        },
    )
    batch = osvpy.scan_docker_archive(
        archive, offline=True, database_path=database, all_packages=inventory
    )
    assert not batch.complete
    assert batch.errors[0][1].code == "offline_unavailable"
    assert "PyPI" in batch.errors[0][1].message
    assert not batch.findings  # Discard even the valid Ubuntu partial finding.
    python_db = database / "osv-scalibr/PyPI/all.zip"
    python_db.parent.mkdir()
    with zipfile.ZipFile(python_db, "w"):
        pass
    batch = osvpy.scan_docker_archive(
        archive, offline=True, database_path=database, all_packages=inventory
    )
    assert batch.complete
    assert {p.data.name for p in batch.packages} == (
        {"openssl", "example"} if inventory else {"openssl"}
    )
    assert not batch.images[0].data.metadata.no_packages


def test_malformed_archive_isolated_from_success(
    archive_pair: tuple["Path", "Path"], tmp_path: "Path"
) -> None:
    malformed = tmp_path / "malformed.tar"
    malformed.write_bytes(b"not a Docker archive")
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [
            executor.submit(
                osvpy.scan_docker_archive,
                malformed,
                archive_pair[0],
                offline=True,
                database_path=archive_pair[1],
            )
            for _ in range(8)
        ]
        for future in futures:
            result = future.result(timeout=30)
            assert [im.complete for im in result.images] == [False, True]
            assert result.errors[0][1].code == "scan_error"
