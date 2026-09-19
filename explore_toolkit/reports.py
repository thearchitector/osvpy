"""Configurable upstream responses for native reporting experiments."""

import copy
import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


def upstream_image(
    image: int = 0,
    *,
    packages: int = 2000,
    overlap: float = 1.0,
    fanout: int = 10,
    fanout_fraction: float = 0.7,
    details_bytes: int = 0,
    alias_only: bool = False,
    license_violations: tuple[str, ...] = (),
) -> "dict[str, Any]":
    """Build one upstream response with consistent package/advisory relationships.

    overlap is the fraction of package identities shared across image numbers.
    fanout_fraction selects packages whose advisories affect groups of fanout
    packages; remaining packages have individual advisories. Groups never cross
    the shared/image-specific boundary. alias_only gives each image distinct
    advisory IDs while keeping shared vulnerability aliases. Each call owns its
    graph, with intentional advisory sharing within the graph.
    """
    if packages < 0 or fanout < 1 or details_bytes < 0:
        raise ValueError(
            "packages/details_bytes must be nonnegative; fanout must be positive"
        )
    if not 0 <= overlap <= 1 or not 0 <= fanout_fraction <= 1:
        raise ValueError("overlap and fanout_fraction must be between zero and one")
    data: dict[str, Any] = json.loads(
        (Path(__file__).parent / "data/complete_response.json").read_text()
    )
    template = data["result"]["results"][0]["packages"][0]
    shared, grouped = int(packages * overlap), int(packages * fanout_fraction)
    records = []
    for index in range(packages):
        package = copy.deepcopy(template)
        namespace = "shared" if index < shared else f"image-{image}"
        name = f"{namespace}-package-{index}"
        package["package"].update(
            name=name, os_package_name=name, commit="", deprecated=False
        )
        package["license_violations"] = list(license_violations)
        package["vulnerabilities"] = []
        records.append(package)
    start = 0
    while start < packages:
        end = min(start + fanout, grouped) if start < grouped else start + 1
        if start < shared:
            end = min(end, shared)
        namespace = "shared" if end <= shared else f"image-{image}"
        advisory = copy.deepcopy(template["vulnerabilities"][0])
        advisory_id = f"OSVPY-{namespace}-{start}"
        if alias_only:
            advisory_id += f"-image-{image}"
        alias = f"CVE-{namespace}-{start}"
        advisory.update(
            id=advisory_id, aliases=[alias], details="x" * details_bytes, affected=[]
        )
        for package in records[start:end]:
            affected = copy.deepcopy(template["vulnerabilities"][0]["affected"][0])
            name = package["package"]["name"]
            affected["package"].update(name=name, purl=f"pkg:deb/ubuntu/{name}@1.0")
            advisory["affected"].append(affected)
            package["vulnerabilities"] = [advisory]
            package["groups"] = [
                {
                    "ids": [advisory_id],
                    "aliases": [advisory_id, alias],
                    "max_severity": "9.8",
                    "experimental_analysis": {advisory_id: {"called": True}},
                }
            ]
        start = end
    data["result"]["results"][0]["packages"] = records
    digest = "sha256:" + hashlib.sha256(f"image-{image}".encode()).hexdigest()
    data["result"]["image_metadata"]["layer_metadata"][0]["diff_id"] = digest
    data["request"] = {"image": f"image-{image}", "all_packages": True}
    return data
