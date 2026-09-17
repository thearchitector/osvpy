"""Configurable upstream reports and an adapter to the current native report format."""

import copy
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from osvpy import BatchResult
from osvpy._store import decode

from .native import bridge_workspace

if TYPE_CHECKING:
    from collections.abc import Iterable
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
    data["metadata"].update(
        image_digest=digest, source="docker_archive", duration_seconds=0
    )
    data["request"] = {
        "image": f"image-{image}",
        "source": "docker_archive",
        "all_packages": True,
    }
    return data


def materialize_reports(
    images: "Iterable[dict[str, Any]]",
    output: Path,
    *,
    independent: bool = False,
    timeout: float = 300,
) -> tuple[list[Path], dict[str, object]]:
    """Project inputs using a temporary copy of the current Go bridge.

    A failed input can be supplied as {"request": {"image": ...}, "error":
    {"code": "scan_error", "message": ...}}. Outputs are private wire fixtures,
    not a supported interchange format. Use a fresh output directory per case.
    Fixture generation, input serialization, and Go compilation are not timed.
    """
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="osvpy-inputs-") as directory:
        inputs = []
        for index, image in enumerate(images):
            path = Path(directory) / f"{index}.json"
            path.write_text(json.dumps(image))
            inputs.append(str(path))
        spec = Path(directory) / "spec.json"
        spec.write_text(
            json.dumps({
                "inputs": inputs,
                "output": str(output),
                "independent": independent,
            })
        )
        driver = Path(__file__).with_name("report_driver_test.go")
        with bridge_workspace(extra_files=[driver]) as workspace:
            subprocess.run(
                [
                    "go",
                    "test",
                    "-mod=readonly",
                    "-run",
                    "^TestExploreReports$",
                    "-count=1",
                ],
                cwd=workspace,
                env=os.environ | {"OSVPY_EXPLORE_SPEC": str(spec)},
                capture_output=True,
                text=True,
                check=True,
                timeout=timeout,
            )
    stats = json.loads((output / "native.json").read_text())
    count = len(inputs) if independent else 1
    return [output / f"report-{index}.msgpack" for index in range(count)], stats


def load_report(path: Path) -> BatchResult:
    """Decode a current native fixture for public-view traversal/retention probes."""
    return BatchResult(decode(path.read_bytes()))
