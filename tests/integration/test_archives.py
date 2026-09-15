from collections.abc import Callable
from pathlib import Path

import pytest

import pyosv

pytestmark = pytest.mark.native


@pytest.mark.parametrize("path_type", [str, Path], ids=["string", "path"])
def test_offline_scan_finds_vulnerability_in_unicode_path(
    archive_pair: tuple[Path, Path], path_type: type[str] | type[Path]
) -> None:
    archive, database = archive_pair
    result = pyosv.scan_docker_archive(
        path_type(archive), offline=True, database_path=path_type(database)
    )
    assert [
        (v.id, v.package, v.installed_version, v.fixed_version)
        for v in result.vulnerabilities
    ] == [("PYOSV-TEST-0001", "openssl", "3.0.0-1", "3.0.0-2")]


@pytest.mark.parametrize(
    ("all_packages", "names"), [(False, {"openssl"}), (True, {"openssl", "unaffected"})]
)
def test_all_packages_controls_inventory(
    offline_scan: Callable[..., pyosv.ScanResult], all_packages: bool, names: set[str]
) -> None:
    result = offline_scan(all_packages=all_packages)
    assert {p.package.name for p in result.packages} == names


def test_scan_is_quiet(
    offline_scan: Callable[..., pyosv.ScanResult], capfd: pytest.CaptureFixture[str]
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
