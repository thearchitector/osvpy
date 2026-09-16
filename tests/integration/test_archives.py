from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import pyosv

if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.mark.parametrize("path_type", [str, Path], ids=["string", "path"])
def test_offline_scan_finds_vulnerability_in_unicode_path(
    archive_pair: tuple[Path, Path], path_type: type[str] | type[Path]
) -> None:
    archive, database = archive_pair
    result = pyosv.scan_docker_archive(
        path_type(archive), offline=True, database_path=path_type(database)
    )
    package = result.packages[0]
    vulnerability = result.vulnerabilities[0]
    assert (package.name, package.installed_version) == ("openssl", "3.0.0-1")
    assert vulnerability.id == "PYOSV-TEST-0001"
    assert vulnerability.packages == [package.id]
    assert package.vulnerabilities[0].id == vulnerability.id
    assert package.vulnerabilities[0].fixed_versions == ["3.0.0-2"]


@pytest.mark.parametrize(
    ("all_packages", "names"), [(False, {"openssl"}), (True, {"openssl", "unaffected"})]
)
def test_all_packages_controls_inventory(
    offline_scan: "Callable[..., pyosv.ScanResult]", all_packages: bool, names: set[str]
) -> None:
    result = offline_scan(all_packages=all_packages)
    assert {p.name for p in result.packages} == names


def test_full_details_are_opt_in(
    offline_scan: "Callable[..., pyosv.ScanResult]",
) -> None:
    result = offline_scan(detail="full")
    assert isinstance(result, pyosv.FullScanResult)
    assert result.vulnerabilities[0].advisory.summary == (
        "Synthetic test vulnerability; not a real advisory"
    )
    assert result.vulnerabilities[0].fixed_version == "3.0.0-2"


def test_compact_json_has_no_advisory_copies(
    offline_scan: "Callable[..., pyosv.ScanResult]",
) -> None:
    data = offline_scan().model_dump()
    assert set(data) == {"image", "metadata", "packages", "vulnerabilities", "licenses"}
    assert set(data["vulnerabilities"][0]) == {"id", "aliases", "severity", "packages"}
    assert data["licenses"] is None


def test_invalid_report_detail(offline_scan: "Callable[..., pyosv.ScanResult]") -> None:
    with pytest.raises(ValueError, match="detail must be compact or full"):
        offline_scan(detail="invalid")


def test_offline_license_check_is_not_silently_skipped(
    offline_scan: "Callable[..., pyosv.ScanResult]",
) -> None:
    with pytest.raises(
        pyosv.OfflineDatabaseError, match="License checks require online"
    ):
        offline_scan(allowed_licenses={"MIT"})


def test_scan_is_quiet(
    offline_scan: "Callable[..., pyosv.ScanResult]", capfd: pytest.CaptureFixture[str]
) -> None:
    offline_scan()
    assert capfd.readouterr() == ("", "")


@pytest.mark.parametrize(
    ("name", "error"),
    [("missing", pyosv.ImageNotFoundError), ("invalid", pyosv.ScanError)],
)
def test_unreadable_archive(
    bad_archives: dict[str, Path], name: str, error: type[pyosv.OSVError]
) -> None:
    with pytest.raises(error):
        pyosv.scan_docker_archive(bad_archives[name])


def test_offline_scan_requires_databases(archive_pair: tuple[Path, Path]) -> None:
    with pytest.raises(pyosv.OfflineDatabaseError):
        pyosv.scan_docker_archive(archive_pair[0], offline=True)
