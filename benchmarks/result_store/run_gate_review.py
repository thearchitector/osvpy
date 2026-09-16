import json
import os
import statistics
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
cases = [
    ("fanout_valid", "current", False),
    ("fanout_valid", "eager_pack", True),
    ("fanout_valid", "dense_eager", True),
    ("fanout_valid", "dense_direct", False),
    ("fanout_valid", "dense_direct", True),
    ("fanout_alias", "dense_eager", True),
    ("fanout_alias", "dense_direct", True),
    ("repeated", "dense_direct", True),
    ("mixed", "dense_direct", True),
]
rows = []
for shape, mode, fast in cases:
    values = []
    env = {**os.environ, "PYOSV_LAB_LIBRARY": str(root / "lab.so")}
    if fast:
        env["PYOSV_FAST_EQUALITY"] = "1"
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
        value = json.loads(p.stdout)
        value["fast_equality"] = fast
        values.append(value)
    rows.extend(values)
    med = {
        k: statistics.median(v[k] for v in values) if isinstance(x, (int, float)) else x
        for k, x in values[0].items()
    }
    print(json.dumps(med), flush=True)
    (root / "gate_results.json").write_text(json.dumps(rows, indent=2) + "\n")
