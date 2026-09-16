"""Owned eager storage and derived little-endian relationship indexes."""

import struct
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING

import msgspec

from ._schema import ReportStore

U32 = struct.Struct("<I")
OCCURRENCE = struct.Struct("<4I")
FINDING = struct.Struct("<5I")


if TYPE_CHECKING:
    from collections.abc import Mapping


def pack(values: list[int]) -> bytes:
    return struct.pack(f"<{len(values)}I", *values)


def relationships(report: ReportStore) -> "Mapping[str, tuple[bytes, bytes]]":
    """Derive packed indexes once; they are not part of the wire format."""
    sizes = {
        "image_occurrences": len(report.images),
        "image_packages": len(report.images),
        "image_vulnerable_packages": len(report.images),
        "image_noncompliant_packages": len(report.images),
        "image_vulnerabilities": len(report.images),
        "image_findings": len(report.images),
        "package_present_images": len(report.packages),
        "package_vulnerable_images": len(report.packages),
        "package_noncompliant_images": len(report.packages),
        "package_affected_images": len(report.packages),
        "vulnerability_affected_images": len(report.vulnerabilities),
        "advisory_affected_images": len(report.advisory_sources),
        "vulnerability_findings": len(report.vulnerabilities),
        "advisory_findings": len(report.advisory_sources),
        "package_findings": len(report.packages),
        "occurrence_findings": len(report.occurrences) // 16,
    }
    edges: dict[str, list[list[int]]] = {
        name: [[] for _ in range(size)] for name, size in sizes.items()
    }
    for o, (im, p, _, lic) in enumerate(OCCURRENCE.iter_unpack(report.occurrences)):
        edges["image_occurrences"][im].append(o)
        edges["image_packages"][im].append(p)
        edges["package_present_images"][p].append(im)
        if report.licenses[lic].status == "noncompliant":
            edges["image_noncompliant_packages"][im].append(p)
            edges["package_noncompliant_images"][p].append(im)
            edges["package_affected_images"][p].append(im)
    for f, (o, a, _, _, v) in enumerate(FINDING.iter_unpack(report.findings)):
        im, p, _, _ = OCCURRENCE.unpack_from(report.occurrences, o * 16)
        for name, key, value in (
            ("image_findings", im, f),
            ("image_vulnerabilities", im, v),
            ("image_vulnerable_packages", im, p),
            ("package_vulnerable_images", p, im),
            ("package_affected_images", p, im),
            ("vulnerability_affected_images", v, im),
            ("advisory_affected_images", a, im),
            ("vulnerability_findings", v, f),
            ("advisory_findings", a, f),
            ("package_findings", p, f),
            ("occurrence_findings", o, f),
        ):
            edges[name][key].append(value)
    result = {}
    for name, members in edges.items():
        offsets = [0]
        values: list[int] = []
        for group in members:
            values.extend(sorted(set(group)))
            offsets.append(len(values))
        result[name] = pack(offsets), pack(values)
    return MappingProxyType(result)


@dataclass(frozen=True, slots=True)
class Store:
    report: ReportStore
    indexes: "Mapping[str, tuple[bytes, bytes]]" = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "indexes", relationships(self.report))

    def members(self, name: str, index: int) -> tuple[bytes, int, int]:
        offsets, members = self.indexes[name]
        start = U32.unpack_from(offsets, index * 4)[0]
        stop = U32.unpack_from(offsets, (index + 1) * 4)[0]
        return members, start, stop


_decoder = msgspec.msgpack.Decoder(ReportStore)


def decode(payload: bytes) -> Store:
    return Store(_decoder.decode(payload))
