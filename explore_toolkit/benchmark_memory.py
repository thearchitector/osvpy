"""Measure each report lifecycle in a fresh process (Linux/macOS)."""

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .native import bridge_workspace
from .processes import ROOT


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--source-dir", type=Path, default=ROOT / "go")
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("--repeat must be positive")
    probe = Path(__file__).with_name("data") / "memory_benchmark_test.go"
    with (
        bridge_workspace(
            source=args.source_dir, extra_files=[probe], include_tests=True
        ) as workspace,
        tempfile.TemporaryDirectory(prefix="osvpy-memory-") as directory,
    ):
        binary = Path(directory) / "report.test"
        subprocess.run(
            ["go", "test", "-c", "-o", str(binary)], cwd=workspace, check=True
        )
        for workload in ("fully_overlapping", "no_overlap"):
            for run in range(1, args.repeat + 1):
                # wait4 returns this child's high-water RSS, excluding compilation
                # and previous runs. File output avoids pipe-buffer deadlocks.
                with tempfile.TemporaryFile(mode="w+") as output:
                    with subprocess.Popen(
                        [
                            str(binary),
                            "-test.run=^$",
                            f"-test.bench=^BenchmarkReportLifecycle$/^{workload}$",
                            "-test.benchmem",
                            "-test.benchtime=1x",
                        ],
                        stdout=output,
                        stderr=subprocess.STDOUT,
                    ) as process:
                        _, status, usage = os.wait4(process.pid, 0)
                        process.returncode = os.waitstatus_to_exitcode(status)
                    output.seek(0)
                    print(output.read(), end="")
                rss_bytes = usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024)
                print(
                    f"{workload} run={run} process-peak-RSS-B={rss_bytes}", flush=True
                )
                if process.returncode:
                    raise SystemExit(process.returncode)


if __name__ == "__main__":
    main()
