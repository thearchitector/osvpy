import asyncio
import pickle

import pytest

import osvpy

from .advisories import SUMMARY


def test_public_report(package_image: str) -> None:
    report = asyncio.run(osvpy.scan(package_image, package_image, workers=2))
    assert report.complete
    assert [im.requested for im in report.images] == [package_image, package_image]
    (package,) = report.packages
    assert (package.name, package.version, package.ecosystem) == (
        "example",
        "1.0",
        "PyPI",
    )
    assert [im.index for im in package.present_images] == [0, 1]
    assert tuple(package.vulnerable_images) == tuple(report.images)
    assert not package.noncompliant_images
    assert tuple(package.affected_images) == tuple(report.images)
    (vulnerability,) = report.vulnerabilities
    assert vulnerability.id == "CVE-2026-12345"
    assert tuple(vulnerability.aliases) == ("OSVPY-EXAMPLE",)
    assert tuple(vulnerability.affected_images) == tuple(report.images)
    assert tuple(vulnerability.findings) == tuple(report.findings)
    (advisory,) = report.advisory_sources
    assert advisory.summary == SUMMARY
    assert advisory.modified == "2026-01-01T00:00:00.123456789Z"
    assert advisory.published is None
    assert advisory.withdrawn is None
    assert advisory.database_severity is None
    assert advisory.references[0].url == "https://example.test/advisory"
    assert advisory.severities[0].type == "CVSS_V3"
    assert tuple(advisory.findings) == tuple(report.findings)
    for image in report.images:
        assert image.metadata.image_digest.startswith("sha256:")
        assert image.metadata.scanner_version == "2.6.0"
        assert image.metadata.duration_seconds >= 0
        assert not image.metadata.no_packages
        assert not image.diagnostics
        assert tuple(image.packages) == (package,)
        assert tuple(image.vulnerable_packages) == (package,)
        assert tuple(image.vulnerabilities) == (vulnerability,)
        (occurrence,) = image.occurrences
        (finding,) = image.findings
        assert occurrence.image == image
        assert occurrence.package == package
        assert occurrence.context.path
        assert occurrence.context.layer
        assert occurrence.license_assessment.status == "not_evaluated"
        assert occurrence.license_assessment.policy is None
        assert tuple(occurrence.findings) == (finding,)
        assert finding.occurrence == occurrence
        assert finding.advisory_source == advisory
        assert finding.vulnerability == vulnerability
        assert finding.assessment.called is None
        assert finding.assessment.unimportant is None
        assert finding.fix_evidence.status == "reported"
        assert tuple(finding.fix_evidence.versions) == ("2.0",)


def test_immutable_sequences_and_identity(package_image: str) -> None:
    report = asyncio.run(osvpy.scan(package_image, package_image))
    other = asyncio.run(osvpy.scan(package_image))
    package = report.packages[0]
    assert package == report.packages[-1]
    assert hash(package) == hash(report.packages[-1])
    assert package != other.packages[0]
    assert report != other
    assert report.images == report.images
    assert len({package, report.packages[0], other.packages[0]}) == 2
    assert report.images[:] == tuple(report.images)
    assert report.images[::-1] == tuple(reversed(report.images))
    assert report.images[-20:20:2] == (report.images[0],)
    assert report.images[1:0] == ()
    assert report.images.count(report.images[0]) == 1
    assert report.images.index(report.images[1]) == 1
    images = tuple(report.images)
    for step in (1, -1, 2, -2, 10**100, -(10**100)):
        for start in (None, -(10**100), -1, 0, 1, 10**100):
            assert report.images[start::step] == images[start::step]
    assert report.images.count(other.images[0]) == 0
    assert report.images.index(report.images[1], -1, 10**100) == 1
    with pytest.raises(ValueError, match="not in sequence"):
        report.images.index(report.images[0], 1)
    for index in (2, -3, 10**100):
        with pytest.raises(IndexError):
            _ = report.images[index]
    with pytest.raises(TypeError):
        _ = report.images[1.5]  # type: ignore[call-overload]
    with pytest.raises(ValueError, match="slice step"):
        _ = report.images[::0]
    with pytest.raises((AttributeError, TypeError)):
        package.name = "changed"  # type: ignore[misc]
    with pytest.raises((AttributeError, TypeError)):
        report.images[0] = report.images[1]  # type: ignore[index]
    for value in (report, package, report.images, report.images[0].metadata):
        with pytest.raises(TypeError):
            pickle.dumps(value)
        with pytest.raises(TypeError):
            type(value)()
        constructor: type[object] = type(value)
        with pytest.raises(TypeError):
            constructor.__new__(constructor)
    child = report.findings[0]
    sequence = report.images[1].occurrences
    del report
    assert child.occurrence.package.name == "example"
    assert sequence[0].package == package


def test_empty_and_failed_batches() -> None:
    batch = asyncio.run(osvpy.scan())
    assert batch.complete
    assert not batch.images
    assert not batch.findings
    invalid = "é\x00" * 1000
    failed = asyncio.run(osvpy.scan(invalid, "BAD IMAGE"))
    assert not failed.complete
    assert failed.images[0].requested == invalid
    assert [i for i, _ in failed.errors] == [0, 1]
    assert all(error.code == "invalid_image" for _, error in failed.errors)
    assert failed.images[0].os is None
