"""Small reporting layer over generated Pydantic models."""

from contextlib import suppress
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError
from pydantic import BaseModel, computed_field

from ._generated import (
    Advisory,
    FullScanData,
    LayerMetadata,
    Package,
    PackageInfo,
    ScanMetadata,
    ScanResult,
    SourceInfo,
)
from ._generated import NativeResponse as _NativeResponse

if TYPE_CHECKING:
    from collections.abc import Iterator

_CVSS_PARSERS = {"CVSS_V2": CVSS2, "CVSS_V3": CVSS3, "CVSS_V4": CVSS4}

__all__ = [
    "Advisory",
    "FullScanResult",
    "LayerMetadata",
    "Package",
    "PackageInfo",
    "RegistryAuth",
    "ScanMetadata",
    "ScanResult",
    "SourceInfo",
    "Vulnerability",
]


@dataclass(frozen=True)
class RegistryAuth:
    """Explicit registry credentials, excluded from repr."""

    username: str = field(repr=False)
    password: str = field(repr=False)


class Vulnerability(BaseModel):
    """An advisory occurrence with installed-package context and report properties.

    The complete advisory is available through ``advisory``; no data is copied
    into a second hand-maintained advisory schema.
    """

    advisory: Advisory
    installed: PackageInfo
    source: SourceInfo
    image_layer: LayerMetadata | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def id(self) -> str:
        return self.advisory.id or ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def package(self) -> str:
        return self.installed.name

    @computed_field  # type: ignore[prop-decorator]
    @property
    def installed_version(self) -> str:
        return self.installed.version

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ecosystem(self) -> str:
        return self.installed.ecosystem

    @computed_field  # type: ignore[prop-decorator]
    @property
    def layer(self) -> str | None:
        return self.image_layer.diff_id if self.image_layer else None

    def _fix_events(self) -> "Iterator[str]":
        return (
            event.fixed
            for affected in self.advisory.affected or ()
            if affected.package is not None
            and affected.package.name == self.package
            and affected.package.ecosystem == self.ecosystem
            for version_range in affected.ranges or ()
            for event in version_range.events or ()
            if event.fixed is not None
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fixed_versions(self) -> list[str]:
        return list(dict.fromkeys(self._fix_events()))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fixed_version(self) -> str | None:
        fixes = self._fix_events()
        first = next(fixes, None)
        return None if any(fix != first for fix in fixes) else first

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity(self) -> float | None:
        highest = None
        for severity in self.advisory.severity or ():
            parser = _CVSS_PARSERS.get(severity.type or "")
            if parser is not None and severity.score is not None:
                with suppress(CVSSError):
                    score = float(parser(severity.score).scores()[0])
                    if highest is None or score > highest:
                        highest = score
        return highest


class FullScanResult(FullScanData):
    """Complete generated result fields plus convenient flattened report views."""

    @computed_field  # type: ignore[prop-decorator]
    @cached_property
    def packages(self) -> list[Package]:
        return [p for source in self.sources or [] for p in source.packages or []]

    @computed_field  # type: ignore[prop-decorator]
    @cached_property
    def vulnerabilities(self) -> list[Vulnerability]:
        layers = self.image_metadata.layers or [] if self.image_metadata else []
        return [
            Vulnerability(
                advisory=advisory,
                installed=package.package,
                source=source.source,
                image_layer=layers[package.package.image_origin.layer_index]
                if package.package.image_origin is not None
                else None,
            )
            for source in self.sources or []
            for package in source.packages or []
            for advisory in package.vulnerabilities or []
        ]


class NativeResponse(_NativeResponse):
    result: FullScanResult | None = None
