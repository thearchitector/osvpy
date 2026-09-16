"""Measure production schema retention, native decoding and traversal.

Run: uv run python -m benchmarks.production_store --output /tmp/production.json
Native fixture construction is untraced. Python retention is measured separately
from untraced decode/traversal. Go samples are checkpoints, not a claim of
continuous peak coverage; C capacity at finish is exact. No real scan is timed.
"""

import argparse
import gc
import json
import os
import resource
import subprocess
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

from osvpy import BatchResult
from osvpy._store import decode


def measure(paths: list[Path]) -> dict[str, float | int]:
    gc.collect()
    tracemalloc.start()
    before = tracemalloc.get_traced_memory()[0]
    reports = [BatchResult(decode(p.read_bytes())) for p in paths]
    # Exercise final facade paths before measuring: no expanded list cache.
    for batch in reports:
        for image in batch.images:
            for finding in image.findings:
                _ = (
                    finding.fix_evidence.versions,
                    finding.advisory_source,
                    finding.occurrence.package,
                )
        for package in batch.packages:
            _ = package.present_images, package.affected_images
    gc.collect()
    retained, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    del reports
    payloads = [p.read_bytes() for p in paths]
    start = time.perf_counter()
    reports = [BatchResult(decode(p)) for p in payloads]
    decode_seconds = time.perf_counter() - start
    start = time.perf_counter()
    findings = sum(len(f.fix_evidence.versions) for b in reports for f in b.findings)
    traversal = time.perf_counter() - start
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {
        "retained_bytes": retained - before,
        "python_peak_bytes": peak - before,
        "decode_seconds": decode_seconds,
        "traversal_seconds": traversal,
        "fix_strings_visited": findings,
        "max_rss_bytes": rss * (1 if sys.platform == "darwin" else 1024),
        "retained_c_bytes": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--case")
    args = parser.parse_args()
    if args.worker:
        print(
            json.dumps(measure(sorted(args.worker.glob(f"{args.case}-[0-9]*.msgpack"))))
        )
        return
    with tempfile.TemporaryDirectory() as directory:
        root = Path(__file__).resolve().parents[1]
        subprocess.run(
            ["go", "test", "-run", "TestProductionMemoryFixtures", "-count=1"],
            cwd=root / "go",
            env=os.environ | {"OSVPY_MEMORY_DIR": directory},
            check=True,
        )
        native = json.loads((Path(directory) / "native.json").read_text())
        results = {}
        for case in native:
            output = subprocess.check_output(
                [
                    sys.executable,
                    "-m",
                    "benchmarks.production_store",
                    "--worker",
                    directory,
                    "--case",
                    case["case"],
                ],
                cwd=root,
            )
            results[case["case"]] = case | json.loads(output)
        for name, budget in (("single", 4), ("identical", 6), ("partial", 23)):
            assert results[name]["retained_bytes"] <= budget * 1024 * 1024, (
                name,
                results[name],
            )
        assert (
            results["disjoint"]["retained_bytes"]
            <= 1.1 * results["disjoint-independent"]["retained_bytes"]
        )
        assert (
            results["large"]["retained_bytes"]
            <= 1.01 * results["identical"]["retained_bytes"]
        )
        encoded = json.dumps(results, indent=2) + "\n"
        if args.output:
            args.output.write_text(encoded)
        else:
            print(encoded)


if __name__ == "__main__":
    main()
