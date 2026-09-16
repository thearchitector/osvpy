"""Measure Python protobuf runtime/schema RSS increment without dynamic loading."""

import json
import statistics
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
code = f"""
import sys,json,gc
sys.path.insert(0,{str(root)!r})
import store_review as s
gc.collect();s.lib.lab_gc();before=s.rss()
from advisory_pb2_probe import Advisory
gc.collect();s.lib.lab_gc();after=s.rss()
print(json.dumps(dict(before_MiB=before,after_MiB=after,increment_MiB=after-before)))
"""
rows = []
for _ in range(5):
    process = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    rows.append(json.loads(process.stdout))
print(
    json.dumps({
        "median_increment_MiB": statistics.median(r["increment_MiB"] for r in rows),
        "samples": rows,
    })
)
(root / "runtime_results.json").write_text(json.dumps(rows, indent=2) + "\n")
