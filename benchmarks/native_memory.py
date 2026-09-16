"""Compare concurrent native calls with the Python admission gate.

Run each mode in a fresh process, for example:
    python -m benchmarks.native_memory --mode gated --details-mib 4

Requires the development environment and a freshly built native library.
"""

import argparse
import json
import resource
import sys
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from osvpy import _native
from tests.fixtures import make_fixture


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["gated", "ungated"], required=True)
    parser.add_argument("--details-mib", type=int, default=4)
    parser.add_argument("--scans", type=int, default=8)
    args = parser.parse_args()
    if args.details_mib < 0 or args.scans < 1:
        parser.error("details-mib must be nonnegative and scans must be positive")

    with tempfile.TemporaryDirectory() as directory:
        archive, database = make_fixture(Path(directory))
        database_zip = database / "osv-scalibr/Ubuntu/all.zip"
        with zipfile.ZipFile(database_zip) as source:
            advisory = json.loads(source.read("OSVPY-TEST-0001.json"))
        advisory["details"] = "x" * (args.details_mib * 1024 * 1024)
        with zipfile.ZipFile(database_zip, "w") as output:
            output.writestr("OSVPY-TEST-0001.json", json.dumps(advisory))
        del advisory

        request = {
            "source": "docker_archive",
            "offline": True,
            "database_path": str(database),
        }
        call = _native.scan if args.mode == "gated" else _native.NativeLibrary().call
        call((str(archive),), request)

        def scan(_: int) -> bool:
            return call((str(archive),), request).complete

        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=4) as pool:
            count = sum(pool.map(scan, range(args.scans)))
        elapsed = time.perf_counter() - start
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # Linux reports KiB; macOS reports bytes.
        rss_mib = rss / (1024 * 1024 if sys.platform == "darwin" else 1024)
        print(
            json.dumps({
                "mode": args.mode,
                "details_mib": args.details_mib,
                "scans": count,
                "seconds": elapsed,
                "max_rss_mib": rss_mib,
            })
        )


if __name__ == "__main__":
    main()
