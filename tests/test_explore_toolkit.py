"""The reusable workloads produce usable reports and isolated worker results."""

import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from explore_toolkit.processes import medians, run_fresh
from explore_toolkit.reports import load_report, materialize_reports, upstream_image

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize("independent", [False, True])
def test_report_workloads_preserve_overlap_aliases_and_failures(
    tmp_path: "Path", independent: bool
) -> None:
    paths, _ = materialize_reports(
        [
            upstream_image(
                0,
                packages=12,
                overlap=0.5,
                fanout=3,
                fanout_fraction=0.5,
                alias_only=True,
            ),
            {
                "request": {"image": "missing"},
                "error": {"code": "scan_error", "message": "fixture"},
            },
            upstream_image(
                1,
                packages=12,
                overlap=0.5,
                fanout=3,
                fanout_fraction=0.5,
                alias_only=True,
            ),
        ],
        tmp_path,
        independent=independent,
    )
    reports = [load_report(path) for path in paths]
    images = [image for report in reports for image in report.images]
    assert [image.data.requested for image in images] == [
        "image-0",
        "missing",
        "image-1",
    ]
    assert [image.complete for image in images] == [True, False, True]
    assert len(images[0].packages) == len(images[2].packages) == 12
    assert not images[1].findings
    assert sum(len(report.packages) for report in reports) == (
        24 if independent else 18
    )
    assert sum(len(report.vulnerabilities) for report in reports) == (
        16 if independent else 14
    )
    assert sum(len(report.advisory_sources) for report in reports) == 16


def test_worker_samples_and_failures(tmp_path: "Path") -> None:
    worker = tmp_path / "worker with spaces.py"
    worker.write_text(
        "import json, os\n"
        "print(json.dumps({'metric': int(os.environ['EXPLORATION_SAMPLE'])}))\n"
    )
    samples = run_fresh(
        [sys.executable, str(worker)],
        repeats=2,
        env={"EXPLORATION_SAMPLE": "7"},
        cwd=tmp_path,
    )
    assert samples == [{"metric": 7}, {"metric": 7}]
    assert medians(samples, "metric") == {"metric": 7.0}
    worker.write_text("raise SystemExit('failed worker')\n")
    with pytest.raises(subprocess.CalledProcessError) as failure:
        run_fresh([sys.executable, str(worker)], repeats=1, cwd=tmp_path)
    assert "failed worker" in failure.value.stderr
