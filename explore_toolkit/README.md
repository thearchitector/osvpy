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
| `images.py` | `registry_resources()` builds in-memory OCI layers and a two-platform image index from file contents. `serve_registry()` serves them locally with optional credentials, failures, and a request barrier. |
| `reports.py` | `upstream_image()` generates coherent package/advisory workloads with configurable overlap, advisory fanout, alias sharing, descriptions, and license violations. The generator supplies upstream inputs to isolated native experiments. |
| `data/complete_response.json` | Full-information upstream response template used by the report generator; preserves less common advisory and image fields. |
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
import asyncio
import json
from dataclasses import asdict

import osvpy
from explore_toolkit.images import registry_resources, serve_registry
from explore_toolkit.measure import peak_rss_bytes, retained, timed

with serve_registry(registry_resources()) as image:

    def group():
        async def run():
            return await asyncio.gather(*(osvpy.scan(image) for _ in range(4)))

        return asyncio.run(run())

    seconds = timed(group, repeats=3)
    reports, memory = retained(group)
    print(
        json.dumps({
            "seconds": seconds,
            "peak_rss_bytes": peak_rss_bytes(),
            **asdict(memory),
        })
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
threshold. For acquisition tests, use `serve_registry()` as a
context manager. Passing the same `threading.Barrier(2)` to two registries allows
an overlap check without speed assertions; manifest requests have a bounded wait.

## Study result construction and retention without scanning

`reports.upstream_image()` produces independently configurable upstream inputs.
Use `overlap`, `fanout`, `details_bytes`, and `alias_only` to vary reporting
workloads. Project these inputs inside an isolated native experiment; production
results have no serialization or bulk-export API.

The hard-cutover experiment is in ignored
`experiments/cython_cutover/`. It preserves a runnable pre-cutover source tree
and fixture definitions, compares the actual compiled Cython properties against
that baseline, and records five fresh-process timings separately from allocation
passes. Historical prototype measurements remain in `experiments/cython_probe/`;
its binding is retired.

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
- Go heap samples are checkpoints, not continuous peaks. Native memory and Python tracing are
  separate allocation measures. Do not add independently sampled peaks and call
  the sum an observed process peak.
- Keep raw repeated samples in ignored files. Compare equivalent setup and
  workloads, and record environment/toolchain versions alongside your findings.
