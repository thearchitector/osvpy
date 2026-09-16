import json
import os
import statistics
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
cases = [
    ("dense_eager", "pinned", "none"),
    ("dense_raw", "pinned", "none"),
    ("dense_split", "pinned", "none"),
    ("dense_split", "pinned", "64"),
    ("raw_copy", "pinned", "none"),
    ("raw", "c", "none"),
]
rows = []
env = {**os.environ, "PYOSV_LAB_LIBRARY": str(root / "lab.so")}
for shape in sys.argv[1:] or ["repeated", "unique", "details", "mixed", "fanout"]:
    selected = cases + (
        [
            ("eager_pack", "pinned", "none"),
            ("native_only", "pinned", "none"),
            ("proto", "pinned", "none"),
            ("flat", "pinned", "none"),
        ]
        if shape == "fanout"
        else []
    )
    for mode, handoff, cache in selected:
        values = []
        for _ in range(3):
            p = subprocess.run(
                [
                    sys.executable,
                    str(root / "store_review.py"),
                    shape,
                    mode,
                    handoff,
                    cache,
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
        (root / "dense_results.json").write_text(json.dumps(rows, indent=2) + "\n")
