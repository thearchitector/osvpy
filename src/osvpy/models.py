"""Public native result views and lightweight registry credentials."""

from dataclasses import dataclass, field

from ._native import (
    AdvisorySource,
    BatchResult,
    Finding,
    ImageResult,
    IndexedSequence,
    NativeError,
    Occurrence,
    Package,
    ReportAssessment,
    ReportContext,
    ReportFix,
    ReportLicense,
    ReportReference,
    ReportSeverity,
    ScanMetadata,
    Vulnerability,
)


@dataclass(frozen=True, slots=True)
class RegistryAuth:
    """Explicit credentials, excluded from repr."""

    username: str = field(repr=False)
    password: str = field(repr=False)


__all__ = [
    "AdvisorySource",
    "BatchResult",
    "Finding",
    "ImageResult",
    "IndexedSequence",
    "NativeError",
    "Occurrence",
    "Package",
    "RegistryAuth",
    "ReportAssessment",
    "ReportContext",
    "ReportFix",
    "ReportLicense",
    "ReportReference",
    "ReportSeverity",
    "ScanMetadata",
    "Vulnerability",
]
