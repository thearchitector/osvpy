import json
import statistics
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
cases = [
    ("eager_json", "pinned", "none"),
    ("eager_pack", "pinned", "none"),
    ("eager_pack", "callback", "none"),
    ("eager_pack", "c", "none"),
    ("raw", "pinned", "none"),
    ("raw", "pinned", "64"),
    ("raw", "pinned", "all"),
    ("blob", "pinned", "none"),
    ("proto", "pinned", "none"),
    ("flat", "pinned", "none"),
    ("native_only", "pinned", "none"),
    ("native_only", "pinned", "64"),
]
all_rows = []
for shape in sys.argv[1:] or ["repeated", "unique", "details", "mixed"]:
    for mode, handoff, cache in cases:
        rows = []
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
                text=True,
                capture_output=True,
            )
            if p.returncode:
                raise RuntimeError(p.stderr + p.stdout)
            rows.append(json.loads(p.stdout))
        all_rows.extend(rows)
        med = {
            k: statistics.median(r[k] for r in rows)
            if isinstance(v, (int, float))
            else v
            for k, v in rows[0].items()
        }
        print(json.dumps(med), flush=True)
        (root / "store_results.json").write_text(json.dumps(all_rows, indent=2) + "\n")
