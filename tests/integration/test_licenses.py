from typing import TYPE_CHECKING

import pytest

import osvpy

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    ("allowed", "forbidden"),
    [
        ({"MIT"}, {"osvpy-license-forbidden"}),
        ({"MIT", "GPL-3.0-only"}, set()),
        (set(), {"osvpy-license-allowed", "osvpy-license-forbidden"}),
    ],
)
def test_license_policy(
    licensed_archive: "Path", allowed: set[str], forbidden: set[str]
) -> None:
    result = osvpy.scan_docker_archive(licensed_archive, allowed_licenses=allowed)
    assert result.complete
    assert not result.vulnerabilities
    assert {p.data.name for p in result.images[0].noncompliant_packages} == forbidden
    for o in result.images[0].occurrences:
        assert o.license_assessment.policy == tuple(sorted(allowed))
        assert o.license_assessment.status == "noncompliant"
        assert o.package.noncompliant_images
        assert not o.package.vulnerable_images


def test_license_expression(licensed_archive: "Path") -> None:
    result = osvpy.scan_docker_archive(licensed_archive, allowed_licenses={"MIT"})
    assert result.complete
    (o,) = result.images[0].occurrences
    assert o.license_assessment.violations == ("GPL-3.0-only",)
