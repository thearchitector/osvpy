import json
import os
import statistics
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
env = {**os.environ, "PYOSV_LAB_LIBRARY": str(root / "lab.so")}
rows = []
for shape in ["repeated", "unique", "details", "mixed", "fanout"]:
    for mode in ["dense_direct", "dense_records"]:
        values = []
        for _ in range(3):
            p = subprocess.run(
                [
                    sys.executable,
                    str(root / "store_review.py"),
                    shape,
                    mode,
                    "pinned",
                    "none",
                ],
                env=env,
                text=True,
                capture_output=True,
            )
            if p.returncode:
                raise RuntimeError(p.stderr + p.stdout)
            values.append(json.loads(p.stdout))
        rows.extend(values)
        med = {
            k: statistics.median(v[k] for v in values)
            if isinstance(x, (int, float))
            else x
            for k, x in values[0].items()
        }
        print(json.dumps(med), flush=True)
        (root / "final_results.json").write_text(json.dumps(rows, indent=2) + "\n")
