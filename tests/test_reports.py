import json
from typing import TYPE_CHECKING

import pytest

from osvpy import FullScanResult, Vulnerability

if TYPE_CHECKING:
    from collections.abc import Callable


def test_finding_identifies_installed_package(report: FullScanResult) -> None:
    assert [
        (v.id, v.package, v.installed_version, v.ecosystem)
        for v in report.vulnerabilities
    ] == [
        ("TEST-2026-1", "openssl", "1.0", "Ubuntu:24.04"),
        ("SECOND-ADVISORY", "requests", "2.0", "PyPI"),
    ]


def test_finding_attributes_source_and_layer(report: FullScanResult) -> None:
    assert [(v.source.path, v.layer) for v in report.vulnerabilities] == [
        ("var/lib/dpkg/status", "sha256:layer"),
        ("app/requirements.txt", "sha256:second"),
    ]


@pytest.mark.parametrize(
    ("events", "versions", "single"),
    [
        ([{"introduced": "0"}, {"last_affected": "1.0"}, {"limit": "2.0"}], [], None),
        ([{"fixed": "1.1"}], ["1.1"], "1.1"),
        ([{"fixed": "1.1"}, {"fixed": "1.1"}], ["1.1"], "1.1"),
        ([{"fixed": "1.1"}, {"fixed": "2.1"}], ["1.1", "2.1"], None),
    ],
    ids=["no-fix", "one-fix", "duplicate-fix", "branch-fixes"],
)
def test_fix_summary(
    finding_factory: "Callable[..., Vulnerability]",
    events: list[dict[str, str]],
    versions: list[str],
    single: str | None,
) -> None:
    finding = finding_factory(
        affected=[
            {
                "package": {"name": "openssl", "ecosystem": "Ubuntu:24.04"},
                "ranges": [{"events": events}],
            }
        ]
    )
    assert finding.fixed_versions == versions
    assert finding.fixed_version == single


@pytest.mark.parametrize(
    "package",
    [
        None,
        {"name": "other", "ecosystem": "Ubuntu:24.04"},
        {"name": "openssl", "ecosystem": "Debian:12"},
    ],
    ids=["no-package", "other-name", "other-ecosystem"],
)
def test_fixes_exclude_other_packages(
    finding_factory: "Callable[..., Vulnerability]", package: dict[str, str] | None
) -> None:
    finding = finding_factory(
        affected=[{"package": package, "ranges": [{"events": [{"fixed": "99"}]}]}]
    )
    assert finding.fixed_versions == []


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ([], None),
        ([{"type": "UNKNOWN", "score": "CRITICAL"}], None),
        ([{"type": "CVSS_V3", "score": "invalid"}], None),
        ([{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}], 7.5),
        (
            [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            ],
            9.8,
        ),
        (
            [
                {
                    "type": "CVSS_V4",
                    "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                }
            ],
            10.0,
        ),
    ],
    ids=["absent", "unknown", "malformed", "cvss2", "cvss3", "cvss4"],
)
def test_severity_summary(
    finding_factory: "Callable[..., Vulnerability]",
    severity: list[dict[str, str]],
    expected: float | None,
) -> None:
    finding = finding_factory(severity=severity)
    assert finding.severity == expected


def test_severity_uses_highest_available_score(
    finding_factory: "Callable[..., Vulnerability]",
) -> None:
    finding = finding_factory(
        severity=[
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
            {"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
        ]
    )
    assert finding.severity == pytest.approx(9.8)


def test_computed_properties_reflect_advisory_mutations(
    finding_factory: "Callable[..., Vulnerability]",
) -> None:
    finding = finding_factory(
        affected=[
            {
                "package": {"name": "openssl", "ecosystem": "Ubuntu:24.04"},
                "ranges": [{"events": [{"fixed": "1.1"}, {"fixed": "1.1"}]}],
            }
        ],
        severity=[{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}],
    )
    assert finding.fixed_version == "1.1"
    assert finding.severity == pytest.approx(7.5)
    assert finding.advisory.affected is not None
    ranges = finding.advisory.affected[0].ranges
    assert ranges is not None
    assert ranges[0].events is not None
    ranges[0].events[1].fixed = "2.1"
    assert finding.fixed_version is None
    assert finding.fixed_versions == ["1.1", "2.1"]
    assert finding.advisory.severity is not None
    finding.advisory.severity[0].score = "invalid"
    assert finding.severity is None
    finding.installed.name = "other"
    assert finding.fixed_versions == []
    assert finding.fixed_version is None


def test_report_contains_summary_and_advisory_details(report: FullScanResult) -> None:
    finding = json.loads(report.model_dump_json())["vulnerabilities"][0]
    assert finding["fixed_version"] == "1.1"
    assert finding["advisory"]["credits"][0]["name"] == "Researcher"
    assert finding["advisory"]["modified"] == "2026-02-02T00:00:00.123456789Z"


def test_full_report_can_omit_duplicated_views(report: FullScanResult) -> None:
    data = json.loads(report.model_dump_json(exclude_computed_fields=True))
    assert "vulnerabilities" not in data
    assert "packages" not in data
    assert (
        data["sources"][0]["packages"][0]["vulnerabilities"][0]["id"] == "TEST-2026-1"
    )


def test_saved_full_report_preserves_nested_layer_attribution(
    report: FullScanResult,
) -> None:
    saved = report.model_dump_json(exclude_computed_fields=True)
    restored = FullScanResult.model_validate_json(saved)
    finding = Vulnerability.model_validate(
        restored.vulnerabilities[0].model_dump(exclude_computed_fields=True)
    )
    assert finding.installed.image_origin is not None
    assert finding.installed.image_origin.layer_index == 0
    assert finding.layer == "sha256:layer"
    assert finding.source.path == "var/lib/dpkg/status"
    assert finding.id == "TEST-2026-1"
