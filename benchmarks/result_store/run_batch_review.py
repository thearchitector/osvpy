import json
import statistics
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
cases = [(1, 0.7, "batch", "msgpack")]
for overlap in [1.0, 0.7, 0.0]:
    cases.extend([
        (10, overlap, "independent", "msgpack"),
        (10, overlap, "batch", "msgpack"),
        (10, overlap, "batch", "protobuf"),
    ])
rows = []
for n, overlap, mode, codec in cases:
    values = []
    for _ in range(3):
        p = subprocess.run(
            [
                sys.executable,
                str(root / "batch_review.py"),
                str(n),
                str(overlap),
                mode,
                codec,
            ],
            capture_output=True,
            text=True,
        )
        if p.returncode:
            raise RuntimeError(p.stderr + p.stdout)
        values.append(json.loads(p.stdout))
    rows.extend(values)
    print(
        json.dumps({
            k: statistics.median(v[k] for v in values)
            if isinstance(x, (int, float))
            else x
            for k, x in values[0].items()
        }),
        flush=True,
    )
    (root / "batch_results.json").write_text(json.dumps(rows, indent=2) + "\n")
