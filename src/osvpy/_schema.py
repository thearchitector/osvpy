"""Owned MessagePack records. Empty Go slices are omitted and default to tuples."""

from typing import Literal

import msgspec


class Record(msgspec.Struct, frozen=True, kw_only=True):
    pass


class ScanMetadata(Record, frozen=True, kw_only=True):
    scanner_version: str
    source: str
    offline: bool
    all_packages: bool
    image_digest: str = ""
    image_platform: str = ""
    duration_seconds: float
    no_packages: bool
    database_path: str


class NativeError(Record, frozen=True, kw_only=True):
    code: str
    message: str


class ReportImage(Record, frozen=True, kw_only=True):
    requested: str
    metadata: ScanMetadata
    os: str | None
    status: Literal["complete", "failed"]
    diagnostics: tuple[NativeError, ...] = ()


class ReportPackage(Record, frozen=True, kw_only=True):
    name: str
    version: str
    ecosystem: str
    commit: str
    os_package_name: str
    purl: str


class ReportVulnerability(Record, frozen=True, kw_only=True):
    id: str
    aliases: tuple[str, ...] = ()


class ReportSeverity(Record, frozen=True, kw_only=True):
    type: str
    source: str
    vector: str


class ReportReference(Record, frozen=True, kw_only=True):
    type: str
    url: str


class ReportAdvisory(Record, frozen=True, kw_only=True):
    id: str
    aliases: tuple[str, ...] = ()
    summary: str
    modified: str | None
    published: str | None
    withdrawn: str | None
    severities: tuple[ReportSeverity, ...] = ()
    references: tuple[ReportReference, ...] = ()
    database_severity: str | None


class ReportContext(Record, frozen=True, kw_only=True):
    path: str
    source_type: str
    layer: str | None
    dependency_groups: tuple[str, ...] = ()


class ReportAssessment(Record, frozen=True, kw_only=True):
    called: bool | None
    unimportant: bool | None
    max_severity: str


class ReportLicense(Record, frozen=True, kw_only=True):
    licenses: tuple[str, ...] = ()
    policy: tuple[str, ...] = ()
    violations: tuple[str, ...] = ()
    status: Literal["not_evaluated", "unknown", "compliant", "noncompliant"]


class ReportFix(Record, frozen=True, kw_only=True):
    versions: tuple[str, ...] = ()
    status: Literal["reported", "no_reported_fix", "unknown"]
    severities: tuple[ReportSeverity, ...] = ()
    urgencies: tuple[str, ...] = ()


class ReportStore(Record, frozen=True, kw_only=True):
    abi_version: Literal[4]
    schema_version: Literal[2]
    images: tuple[ReportImage, ...] = ()
    packages: tuple[ReportPackage, ...] = ()
    vulnerabilities: tuple[ReportVulnerability, ...] = ()
    advisory_sources: tuple[ReportAdvisory, ...] = ()
    contexts: tuple[ReportContext, ...] = ()
    assessments: tuple[ReportAssessment, ...] = ()
    licenses: tuple[ReportLicense, ...] = ()
    fixes: tuple[ReportFix, ...] = ()
    occurrences: bytes = b""
    findings: bytes = b""
