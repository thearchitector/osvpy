"""Repeat a JSON-producing command in fresh processes, with bounded execution."""

import argparse
import json
import os
import statistics
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]


def run_fresh(
    command: "Sequence[str]",
    *,
    repeats: int = 3,
    timeout: float = 60,
    cwd: Path = ROOT,
    env: "Mapping[str, str] | None" = None,
) -> list[dict[str, object]]:
    """Run without a shell; require one JSON object on each worker's stdout.

    Worker diagnostics belong on stderr. Failed workers raise CalledProcessError
    with their captured output; timeouts raise TimeoutExpired. No samples are
    silently discarded. Pass cwd to run outside this source checkout.
    """
    if repeats < 1 or timeout <= 0:
        raise ValueError("repeats and timeout must be positive")
    samples = []
    for _ in range(repeats):
        worker = subprocess.run(
            command,
            cwd=cwd,
            env=os.environ | dict(env or {}),
            text=True,
            capture_output=True,
            check=True,
            timeout=timeout,
        )
        value = json.loads(worker.stdout)
        if not isinstance(value, dict):
            raise TypeError("worker stdout must contain one JSON object")
        samples.append(value)
    return samples


def medians(samples: list[dict[str, object]], *metrics: str) -> dict[str, float]:
    """Summarize explicitly selected numeric metrics from comparable samples."""
    if not samples:
        raise ValueError("at least one sample is required")
    summary = {}
    for metric in metrics:
        values = []
        for sample in samples:
            value = sample[metric]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{metric} must be numeric in every sample")
            values.append(float(value))
        summary[metric] = statistics.median(values)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--metric", action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("provide a worker command after --")
    samples = run_fresh(command, repeats=args.repeats, timeout=args.timeout)
    print(
        json.dumps(
            {"samples": samples, "medians": medians(samples, *args.metric)}, indent=2
        )
    )


if __name__ == "__main__":
    main()
