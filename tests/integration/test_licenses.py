from typing import TYPE_CHECKING

import pytest

import pyosv

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    ("allowed", "forbidden"),
    [
        ({"MIT"}, {"pyosv-license-forbidden"}),
        ({"MIT", "GPL-3.0-only"}, set()),
        (set(), {"pyosv-license-allowed", "pyosv-license-forbidden"}),
    ],
    ids=["spdx-or-expression", "all-allowed", "none-allowed"],
)
def test_license_only_packages_are_checked(
    licensed_archive: "Path", allowed: set[str], forbidden: set[str]
) -> None:
    result = pyosv.scan_docker_archive(licensed_archive, allowed_licenses=allowed)
    packages = {p.id: p for p in result.packages}
    assert result.vulnerabilities == []
    assert {p.name for p in result.packages} == forbidden
    assert result.licenses.allowed_licenses == sorted(allowed)
    assert {packages[v.package].name for v in result.licenses.violations} == forbidden


def test_license_report_identifies_forbidden_expression(
    licensed_archive: "Path",
) -> None:
    result = pyosv.scan_docker_archive(licensed_archive, allowed_licenses={"MIT"})
    (violation,) = result.licenses.violations
    assert violation.licenses == ["GPL-3.0-only"]
    assert violation.forbidden == ["GPL-3.0-only"]


def test_missing_license_data_is_a_violation(
    archive_pair: tuple["Path", "Path"],
) -> None:
    result = pyosv.scan_docker_archive(archive_pair[0], allowed_licenses={"MIT"})
    assert [v.forbidden for v in result.licenses.violations] == [
        ["UNKNOWN"],
        ["UNKNOWN"],
    ]
