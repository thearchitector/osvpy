# Exploration toolkit

Reusable building blocks for investigating scan behavior, concurrency, result
representations, and memory costs. Run from the repository root with the project
environment (`uv sync --group dev --group local`). These are development tools,
not part of the installed `osvpy` wheel or public API.

Keep **only reusable tools and fixtures** here. Put investigation scripts,
prototypes, patches, logs, measurements, and reports under
`explore_toolkit/experiments/<topic>/`. The toolkit's `.gitignore` ignores new
files by default and explicitly allows maintained components. When promoting a
new reusable component, add it to that allowlist and document it here. Do not
force-add an experiment or its outputs. Regression tests belong in `tests/` or
`go/` and assert observable behavior, not allocation strategies or internal calls.

## Contents

| Component | Purpose |
| --- | --- |
| `images.py` | `make_image()` builds Linux Docker-save archives from file contents. `make_fixture()` provides openssl, an unaffected package, and a local advisory database with configurable installed version and advisory size. `write_database()` writes any ecosystem's advisory ZIP. `registry_resources()` and `serve_registry()` provide a local two-platform OCI registry with optional credentials, status failures, and a request barrier. The behavioral suite uses these same fixtures. |
| `reports.py` | `upstream_image()` generates coherent package/advisory workloads with configurable overlap, advisory fanout, alias sharing, descriptions, and license violations. `materialize_reports()` runs those inputs through the current native reporting boundary, as a batch or independent images. `load_report()` opens the resulting private wire fixture for view traversal. |
| `data/complete_response.json` | Full-information upstream response template used by the report generator; preserves less common advisory and image fields. |
| `report_driver_test.go` | Instrumentation adapter used only inside a temporary Go module by `materialize_reports()`. Records construction/encoding time, sampled Go heap, and C writer capacity. It is not a correctness test or fixed performance gate. |
| `measure.py` | `timed()` collects untraced durations. `retained()` returns the live result and Python allocation measurements. `current_rss_bytes()` and `peak_rss_bytes()` distinguish current RSS from the process lifetime high-water mark. |
| `processes.py` | `run_fresh()` repeats any JSON-producing command with a timeout and isolated process state. `medians()` summarizes selected numeric fields. Also runnable as a small command-line driver. |
| `native.py` | `bridge_workspace()` copies the current flat Go module to a temporary workspace, optionally adding probe files. `build_library()` builds a separate shared library, optionally with race instrumentation. Neither installs a library nor replaces shared Python clients/loaders. |

The tools retain the useful setup and measurement methods from earlier serializer,
batch, memory, and concurrency experiments. Obsolete codecs, generated prototype
bindings, fixed comparison matrices, benchmark budgets, and historical reports
are deliberately not retained.

## Start an investigation

Create `explore_toolkit/experiments/scan_memory.py` with:

```python
import json
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path

import osvpy
from explore_toolkit.images import make_fixture
from explore_toolkit.measure import peak_rss_bytes, retained, timed

with tempfile.TemporaryDirectory() as directory:
    archive, database = make_fixture(Path(directory), details_bytes=4 * 1024 * 1024)

    def scan():
        return osvpy.scan_docker_archive(archive, offline=True, database_path=database)

    def group():
        with ThreadPoolExecutor(max_workers=4) as pool:
            return list(pool.map(lambda _: scan(), range(8)))

    seconds = timed(group, repeats=3)
    peak_rss = peak_rss_bytes()
    reports, memory = retained(group)
    assert all(report.complete for report in reports)
    print(
        json.dumps({"seconds": seconds, "peak_rss_bytes": peak_rss, **asdict(memory)})
    )
```

Run it as a module so imports resolve from the checkout. Each repetition below
starts a fresh Python/Go runtime. The worker must print exactly one JSON object
to stdout; send diagnostic logging to stderr.

```bash
mkdir -p explore_toolkit/experiments
uv run python -m explore_toolkit.processes --repeats 3 --timeout 120 \
    --metric retained_bytes --metric peak_rss_bytes -- \
    python -m explore_toolkit.experiments.scan_memory \
    > explore_toolkit/experiments/scan_memory_results.json
git check-ignore explore_toolkit/experiments/scan_memory.py
```

To compare concurrency levels, parameterize your script's worker count and run
each level in a fresh process. There is no built-in workload matrix or performance
threshold. Prepare all database files before scans start and keep them unchanged
until every scan finishes. For acquisition tests, use `serve_registry()` as a
context manager. Passing the same `threading.Barrier(2)` to two registries allows
an overlap check without speed assertions; manifest requests have a bounded wait.

## Study result construction and retention without scanning

Use a fresh output directory for each case:

```python
from pathlib import Path

from explore_toolkit.measure import retained, timed
from explore_toolkit.reports import load_report, materialize_reports, upstream_image

output = Path("explore_toolkit/experiments/partial_overlap")
paths, native = materialize_reports(
    (upstream_image(i, packages=2000, overlap=0.7) for i in range(10)), output
)
reports, memory = retained(lambda: [load_report(path) for path in paths])
seconds = timed(lambda: sum(len(report.findings) for report in reports))
print(native, memory, seconds)
```

Use `overlap=1` for shared packages, `overlap=0` for disjoint packages,
`fanout=1` for individual advisories, `details_bytes` for large discarded bodies,
and `alias_only=True` for image-specific advisory IDs sharing vulnerability
aliases. `license_violations` varies assessments without changing package identity.
Supply a failed image as `{"request": {"image": "missing"}, "error":
{"code": "scan_error", "message": "synthetic failure"}}`. Set
`independent=True` to emit one report per image instead of one combined batch.

Inputs are generated one image at a time and saved before measurement. The Go
adapter measures projection and encoding, excluding JSON loading, file writing,
and compilation. This does **not** measure scanning or database lookup.
`load_report()` includes disk reading and decoding; preload bytes and use the
private decoder explicitly in a local experiment when measuring decode alone.
Report fixtures use the current private wire format and must be regenerated after
schema changes. The adapter is the only maintained instrumentation coupled to
the native reporting implementation.

## Native experiments

```python
import subprocess
from pathlib import Path

from explore_toolkit.native import bridge_workspace, build_library

scratch = Path("explore_toolkit/experiments/logger")
with bridge_workspace(
    extra_files=[scratch / "probe_test.go"], include_tests=True
) as work:
    subprocess.run(["go", "test", "-race", "./..."], cwd=work, check=True, timeout=120)
    build_library(work, scratch / "libprobe.so")  # Use .dylib on macOS.
```

Modify `work` to compare a prototype; it is removed on context exit, including
when the command fails. Keep built libraries in ignored scratch directories.
Module downloads and build caches use Go's normal environment. The Go executable,
a C compiler, and the toolchain version pinned in `go/go.mod` must be available.
Standalone `go test -race` is required for race checks; Python loading of a
race-instrumented shared library can fail during ThreadSanitizer initialization.

## Interpret measurements

- Times from `timed()` are seconds, with warm-up and Python GC outside each sample.
  Traced allocation passes are separate and must not be used as throughput timings.
- `retained()` keeps the returned object alive, collects unreachable Python data,
  and reports traced retained/peak bytes. It does not measure Go, C, or allocator
  slack. An escaped view can keep an entire result store alive.
- Peak RSS includes imports, runtime initialization, inputs, and warm-up. Current
  RSS is available on Linux only (`None` elsewhere). Neither is a live-object count.
- Go heap samples are checkpoints, not continuous peaks. C writer capacity is
  a separate allocation measure. Do not add independently sampled peaks and call
  the sum an observed process peak.
- Keep raw repeated samples in ignored files. Compare equivalent setup and
  workloads, and record environment/toolchain versions alongside your findings.
