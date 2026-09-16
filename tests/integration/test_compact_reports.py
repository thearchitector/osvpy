from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

    import pyosv


def test_aliases_merge_across_packages_and_keep_package_specific_fixes(
    advisory_scan: "Callable[..., pyosv.ScanResult]",
) -> None:
    result = advisory_scan(
        {"id": "TEST-ONE", "aliases": ["CVE-2026-0001"]},
        {
            "id": "TEST-TWO",
            "aliases": ["TEST-ONE", "CVE-2026-0001"],
            "affected": [
                {
                    "package": {"name": "unaffected", "ecosystem": "Ubuntu:24.04"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "2.0"}],
                        }
                    ],
                }
            ],
        },
    )
    (vulnerability,) = result.vulnerabilities
    assert vulnerability.id == "CVE-2026-0001"
    assert vulnerability.aliases == ["TEST-ONE", "TEST-TWO"]
    assert set(vulnerability.packages) == {p.id for p in result.packages}
    assert {
        p.name: [(v.id, v.fixed_versions) for v in p.vulnerabilities]
        for p in result.packages
    } == {
        "openssl": [("CVE-2026-0001", ["3.0.0-2"])],
        "unaffected": [("CVE-2026-0001", ["2.0"])],
    }


@pytest.mark.parametrize(
    ("vector", "score", "rating"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "medium"),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, "low"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "none"),
    ],
)
def test_compact_severity_score_and_rating(
    advisory_scan: "Callable[..., pyosv.ScanResult]",
    vector: str,
    score: float,
    rating: str,
) -> None:
    result = advisory_scan({"severity": [{"type": "CVSS_V3", "score": vector}]})
    severity = result.vulnerabilities[0].severity
    assert (severity.score, severity.rating) == (score, rating)


def test_missing_severity_is_unknown(
    offline_scan: "Callable[..., pyosv.ScanResult]",
) -> None:
    severity = offline_scan().vulnerabilities[0].severity
    assert severity.score is None
    assert severity.rating == "unknown"


def test_group_reports_only_highest_severity(
    advisory_scan: "Callable[..., pyosv.ScanResult]",
) -> None:
    result = advisory_scan(
        {
            "id": "TEST-LOWER",
            "aliases": ["CVE-2026-0002"],
            "severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}],
        },
        {
            "id": "TEST-HIGHER",
            "aliases": ["CVE-2026-0002"],
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            ],
        },
    )
    (vulnerability,) = result.vulnerabilities
    assert vulnerability.severity.score == pytest.approx(9.8)
    assert vulnerability.severity.rating == "critical"
    assert result.packages[0].vulnerabilities[0].fixed_versions == ["3.0.0-2"]


@pytest.mark.parametrize(
    ("events", "fixes"),
    [
        ([{"introduced": "0"}], []),
        (
            [
                {"introduced": "0"},
                {"fixed": "2.0"},
                {"introduced": "3.0"},
                {"fixed": "4.0"},
            ],
            ["4.0"],
        ),
    ],
    ids=["unfixed", "earlier-fix-does-not-fix-installed-version"],
)
def test_compact_fix_versions(
    advisory_scan: "Callable[..., pyosv.ScanResult]",
    events: list[dict[str, str]],
    fixes: list[str],
) -> None:
    result = advisory_scan({
        "affected": [
            {
                "package": {"name": "openssl", "ecosystem": "Ubuntu:24.04"},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }
        ]
    })
    assert result.packages[0].vulnerabilities[0].fixed_versions == fixes
