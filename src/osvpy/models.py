"""Immutable indexed reporting views; expanded collections are never cached."""

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, overload

from ._store import FINDING, OCCURRENCE, U32

if TYPE_CHECKING:
    from collections.abc import Callable

    from ._schema import (
        NativeError,
        ReportAdvisory,
        ReportAssessment,
        ReportContext,
        ReportFix,
        ReportImage,
        ReportLicense,
        ReportPackage,
        ReportVulnerability,
    )
    from ._store import Store


@dataclass(frozen=True, slots=True)
class RegistryAuth:
    """Explicit credentials, excluded from repr."""

    username: str = field(repr=False)
    password: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class IndexedSequence[T](Sequence[T]):
    _store: "Store"
    _factory: "Callable[[Store, int], T]"
    _size: int
    _members: bytes | None = None
    _start: int = 0

    def __len__(self) -> int:
        return self._size

    @overload
    def __getitem__(self, index: int) -> T: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[T, ...]: ...

    def __getitem__(self, index: int | slice) -> T | tuple[T, ...]:
        if isinstance(index, slice):
            return tuple(self[i] for i in range(*index.indices(len(self))))
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError(index)
        row = (
            index
            if self._members is None
            else U32.unpack_from(self._members, (self._start + index) * 4)[0]
        )
        return self._factory(self._store, row)


@dataclass(frozen=True, slots=True)
class _View:
    _store: "Store" = field(repr=False)
    index: int

    def _members[T](
        self, name: str, factory: "Callable[[Store, int], T]"
    ) -> IndexedSequence[T]:
        members, start, stop = self._store.members(name, self.index)
        return IndexedSequence(self._store, factory, stop - start, members, start)


@dataclass(frozen=True, slots=True)
class Package(_View):
    @property
    def data(self) -> "ReportPackage":
        return self._store.report.packages[self.index]

    @property
    def present_images(self) -> IndexedSequence["ImageResult"]:
        return self._members("package_present_images", ImageResult)

    @property
    def vulnerable_images(self) -> IndexedSequence["ImageResult"]:
        return self._members("package_vulnerable_images", ImageResult)

    @property
    def noncompliant_images(self) -> IndexedSequence["ImageResult"]:
        return self._members("package_noncompliant_images", ImageResult)

    @property
    def affected_images(self) -> IndexedSequence["ImageResult"]:
        return self._members("package_affected_images", ImageResult)

    @property
    def findings(self) -> IndexedSequence["Finding"]:
        return self._members("package_findings", Finding)


@dataclass(frozen=True, slots=True)
class Vulnerability(_View):
    @property
    def data(self) -> "ReportVulnerability":
        return self._store.report.vulnerabilities[self.index]

    @property
    def affected_images(self) -> IndexedSequence["ImageResult"]:
        return self._members("vulnerability_affected_images", ImageResult)

    @property
    def findings(self) -> IndexedSequence["Finding"]:
        return self._members("vulnerability_findings", Finding)


@dataclass(frozen=True, slots=True)
class AdvisorySource(_View):
    @property
    def data(self) -> "ReportAdvisory":
        return self._store.report.advisory_sources[self.index]

    @property
    def affected_images(self) -> IndexedSequence["ImageResult"]:
        return self._members("advisory_affected_images", ImageResult)

    @property
    def findings(self) -> IndexedSequence["Finding"]:
        return self._members("advisory_findings", Finding)


@dataclass(frozen=True, slots=True)
class Occurrence(_View):
    def _row(self) -> tuple[int, int, int, int]:
        return OCCURRENCE.unpack_from(self._store.report.occurrences, self.index * 16)

    @property
    def image(self) -> "ImageResult":
        return ImageResult(self._store, self._row()[0])

    @property
    def package(self) -> Package:
        return Package(self._store, self._row()[1])

    @property
    def context(self) -> "ReportContext":
        return self._store.report.contexts[self._row()[2]]

    @property
    def license_assessment(self) -> "ReportLicense":
        return self._store.report.licenses[self._row()[3]]

    @property
    def findings(self) -> IndexedSequence["Finding"]:
        return self._members("occurrence_findings", Finding)


@dataclass(frozen=True, slots=True)
class Finding(_View):
    def _row(self) -> tuple[int, int, int, int, int]:
        return FINDING.unpack_from(self._store.report.findings, self.index * 20)

    @property
    def occurrence(self) -> Occurrence:
        return Occurrence(self._store, self._row()[0])

    @property
    def advisory_source(self) -> AdvisorySource:
        return AdvisorySource(self._store, self._row()[1])

    @property
    def fix_evidence(self) -> "ReportFix":
        return self._store.report.fixes[self._row()[2]]

    @property
    def assessment(self) -> "ReportAssessment":
        return self._store.report.assessments[self._row()[3]]

    @property
    def vulnerability(self) -> Vulnerability:
        return Vulnerability(self._store, self._row()[4])


@dataclass(frozen=True, slots=True)
class ImageResult(_View):
    @property
    def data(self) -> "ReportImage":
        return self._store.report.images[self.index]

    @property
    def complete(self) -> bool:
        return self.data.status == "complete"

    @property
    def packages(self) -> IndexedSequence[Package]:
        return self._members("image_packages", Package)

    @property
    def occurrences(self) -> IndexedSequence[Occurrence]:
        return self._members("image_occurrences", Occurrence)

    @property
    def vulnerable_packages(self) -> IndexedSequence[Package]:
        return self._members("image_vulnerable_packages", Package)

    @property
    def noncompliant_packages(self) -> IndexedSequence[Package]:
        return self._members("image_noncompliant_packages", Package)

    @property
    def vulnerabilities(self) -> IndexedSequence[Vulnerability]:
        return self._members("image_vulnerabilities", Vulnerability)

    @property
    def findings(self) -> IndexedSequence[Finding]:
        return self._members("image_findings", Finding)


@dataclass(frozen=True, slots=True)
class BatchResult:
    _store: "Store" = field(repr=False)

    @property
    def images(self) -> IndexedSequence[ImageResult]:
        return IndexedSequence(self._store, ImageResult, len(self._store.report.images))

    @property
    def packages(self) -> IndexedSequence[Package]:
        return IndexedSequence(self._store, Package, len(self._store.report.packages))

    @property
    def vulnerabilities(self) -> IndexedSequence[Vulnerability]:
        return IndexedSequence(
            self._store, Vulnerability, len(self._store.report.vulnerabilities)
        )

    @property
    def advisory_sources(self) -> IndexedSequence[AdvisorySource]:
        return IndexedSequence(
            self._store, AdvisorySource, len(self._store.report.advisory_sources)
        )

    @property
    def findings(self) -> IndexedSequence[Finding]:
        return IndexedSequence(
            self._store, Finding, len(self._store.report.findings) // 20
        )

    @property
    def complete(self) -> bool:
        return all(im.complete for im in self.images)

    @property
    def errors(self) -> tuple[tuple[int, "NativeError"], ...]:
        return tuple(
            (im.index, d)
            for im in self.images
            if not im.complete
            for d in im.data.diagnostics
        )
