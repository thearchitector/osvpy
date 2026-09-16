from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import osvpy

if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.mark.parametrize("path_type", [str, Path])
def test_offline_unicode_archive(
    archive_pair: tuple[Path, Path], path_type: type[str] | type[Path]
) -> None:
    archive, db = archive_pair
    batch = osvpy.scan_docker_archive(
        path_type(archive), offline=True, database_path=path_type(db)
    )
    assert batch.complete
    assert batch.packages[0].data.name == "openssl"
    assert batch.packages[0].data.version == "3.0.0-1"
    assert batch.vulnerabilities[0].data.id == "OSVPY-TEST-0001"
    assert batch.findings[0].fix_evidence.versions == ("3.0.0-2",)
    assert batch.images[0].data.os


@pytest.mark.parametrize(
    ("all_packages", "names"), [(False, {"openssl"}), (True, {"openssl", "unaffected"})]
)
def test_inventory_scope(
    offline_scan: "Callable[..., osvpy.BatchResult]",
    all_packages: bool,
    names: set[str],
) -> None:
    result = offline_scan(all_packages=all_packages)
    assert {p.data.name for p in result.packages} == names
    assert result.images[0].data.metadata.all_packages is all_packages


def test_archive_input_preserves_embedded_nul(archive_pair: tuple[Path, Path]) -> None:
    archive, db = archive_pair
    requested = f"{archive}\x00suffix"
    batch = osvpy.scan_docker_archive(requested, offline=True, database_path=db)
    assert not batch.complete
    assert batch.images[0].data.requested == requested
    assert batch.errors[0][1].code == "scan_error"


def test_ordered_partial_and_all_failures(
    archive_pair: tuple[Path, Path], tmp_path: Path
) -> None:
    archive, db = archive_pair
    bad = tmp_path / "missing.tar"
    batch = osvpy.scan_docker_archive(
        archive, bad, archive, offline=True, database_path=db
    )
    assert [im.complete for im in batch.images] == [True, False, True]
    assert [im.data.requested for im in batch.images] == [
        str(archive),
        str(bad),
        str(archive),
    ]
    assert len(batch.packages) == 1
    assert [im.index for im in batch.packages[0].present_images] == [0, 2]
    assert [im.index for im in batch.vulnerabilities[0].affected_images] == [0, 2]
    assert not batch.complete
    assert batch.errors[0][0] == 1
    failed = osvpy.scan_docker_archive(bad, bad)
    assert not failed.complete
    assert len(failed.errors) == 2
    assert not failed.packages


def test_offline_validation(archive_pair: tuple[Path, Path]) -> None:
    with pytest.raises(osvpy.OfflineDatabaseError):
        osvpy.scan_docker_archive(archive_pair[0], offline=True)
    with pytest.raises(osvpy.OfflineDatabaseError):
        osvpy.scan_docker_archive(
            archive_pair[0],
            offline=True,
            database_path=archive_pair[1],
            allowed_licenses={"MIT"},
        )


def test_scan_is_quiet(
    offline_scan: "Callable[..., osvpy.BatchResult]", capfd: pytest.CaptureFixture[str]
) -> None:
    assert offline_scan().complete
    assert capfd.readouterr() == ("", "")
