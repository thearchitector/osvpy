from typing import TYPE_CHECKING

import pytest

import osvpy

if TYPE_CHECKING:
    from collections.abc import Callable


def test_immutable_views(offline_scan: "Callable[..., osvpy.BatchResult]") -> None:
    report = offline_scan()
    with pytest.raises((AttributeError, TypeError)):
        report.packages[0].index = 1  # type: ignore[misc]
    with pytest.raises(AttributeError):
        report.packages[0].data.version = "changed"  # type: ignore[misc]
    assert report.packages[-1].data == report.packages[0].data
    assert len(report.packages[:]) == 1
    with pytest.raises(IndexError):
        _ = report.packages[1]


def test_aliases_keep_package_specific_evidence(
    advisory_scan: "Callable[..., osvpy.BatchResult]",
) -> None:
    result = advisory_scan(
        {"id": "TEST-ONE", "aliases": ["CVE-2026-0001"]},
        {
            "id": "TEST-TWO",
            "aliases": ["TEST-ONE"],
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
    assert result.complete
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].data.id == "CVE-2026-0001"
    assert result.vulnerabilities[0].data.aliases == ("TEST-ONE", "TEST-TWO")
    assert {
        f.occurrence.package.data.name: f.fix_evidence.versions for f in result.findings
    } == {"openssl": ("3.0.0-2",), "unaffected": ("2.0",)}


def test_advisory_preserves_timestamp_precision(
    advisory_scan: "Callable[..., osvpy.BatchResult]",
) -> None:
    result = advisory_scan({"modified": "2026-01-01T00:00:00.123456789Z"})
    assert result.advisory_sources[0].data.modified == "2026-01-01T00:00:00.123456789Z"
    assert result.advisory_sources[0].affected_images[0].index == 0


def test_severity_retains_source_and_vector(
    advisory_scan: "Callable[..., osvpy.BatchResult]",
) -> None:
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    result = advisory_scan({
        "severity": [{"type": "CVSS_V3", "score": vector, "source": "NVD"}]
    })
    severity = result.advisory_sources[0].data.severities[0]
    assert (severity.type, severity.source, severity.vector) == (
        "CVSS_V3",
        "NVD",
        vector,
    )


@pytest.mark.parametrize(
    ("events", "fixes", "status"),
    [
        ([{"introduced": "0"}], (), "no_reported_fix"),
        (
            [
                {"introduced": "0"},
                {"fixed": "2.0"},
                {"introduced": "3.0"},
                {"fixed": "4.0"},
            ],
            ("4.0",),
            "reported",
        ),
    ],
)
def test_distro_fixes(
    advisory_scan: "Callable[..., osvpy.BatchResult]",
    events: list[dict[str, str]],
    fixes: tuple[str, ...],
    status: str,
) -> None:
    result = advisory_scan({
        "affected": [
            {
                "package": {"name": "openssl", "ecosystem": "Ubuntu:24.04"},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }
        ]
    })
    assert result.findings[0].fix_evidence.versions == fixes
    assert result.findings[0].fix_evidence.status == status


@pytest.mark.parametrize("scan", [osvpy.scan_image, osvpy.scan_docker_archive])
def test_empty_scan(scan: "Callable[[], osvpy.BatchResult]") -> None:
    batch = scan()
    assert batch.complete
    assert not batch.images
    assert not batch.findings
