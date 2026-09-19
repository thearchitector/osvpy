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
force-add an experiment or its outputs. `tests/` and `go/` contain isolated unit
behavior tests. Keep implementation probes, historical regression scenarios,
live scanner runs, and local-registry integration investigations in this toolkit.
Do not turn measurements or implementation choices into test assertions.

## Contents

| Component | Purpose |
| --- | --- |
| `images.py` | `registry_resources()` builds in-memory OCI layers and a two-platform image index from file contents. `serve_registry()` serves them locally with optional credentials, failures, and a request barrier. |
| `advisories.py` | `advisory_proxy(packages)` serves caller-supplied OSV responses over HTTPS for isolated scanner experiments. Yields proxy/certificate settings without changing the parent environment. |
| `reports.py` | `upstream_image()` generates coherent package/advisory workloads with configurable overlap, advisory fanout, alias sharing, descriptions, and license violations. The generator supplies upstream inputs to isolated native experiments. |
| `data/complete_response.json` | Full-information upstream response template used by the report generator; preserves less common advisory and image fields. |
| `measure.py` | `timed()` collects untraced durations. `retained()` returns the live result and Python allocation measurements. `current_rss_bytes()` and `peak_rss_bytes()` distinguish current RSS from the process lifetime high-water mark. |
| `processes.py` | `run_fresh()` repeats any JSON-producing command with a timeout and isolated process state. `medians()` summarizes selected numeric fields. Also runnable as a small command-line driver. |
| `native.py` | `bridge_workspace()` copies the current flat Go module to a temporary workspace, optionally adding probe files. `build_library()` builds a separate shared library, optionally with race instrumentation. Neither installs a library nor replaces shared Python clients/loaders. |
| `benchmark_memory.py` | Builds report memory probes in an isolated Go workspace, then measures each lifecycle workload in a fresh process. Reports sampled Go heap peaks and per-process maximum RSS. |
| `data/memory_benchmark_test.go` | Go probes for alias finalization and report ingestion, finalization, and streaming serialization. Injected into the temporary workspace; not part of production Go tests. |
| `data/storage_probe_test.go` | `observeIndexPlan()`, `observeIndexes()`, and `observeRowSizes()` return planning, slab, and layout observations without assertions or thresholds. |

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

## Report lifecycle memory benchmark

```bash
uv run python -m explore_toolkit.benchmark_memory --repeat 3
```

The runner uses `native.bridge_workspace()` to copy the Go module and its tests,
injects `data/memory_benchmark_test.go`, and compiles a temporary test binary.
Each workload runs in a fresh process. Linux/macOS `wait4` supplies that child's
maximum RSS, excluding compilation and previous runs. Use `--source-dir` to
measure another compatible Go checkout with the same injected probes.

The lifecycle probe ingests ten images with 2,000 package occurrences each,
finalizes all tables and 16 indexes, and streams every logical table and
relationship as JSON to a discard sink. Four findings per occurrence exercise
relationship deduplication. Separate cases use fully overlapping or entirely
distinct packages and advisories. The immutable report stays alive throughout
serialization. The fixture also provides `BenchmarkFinishLargeAliasUniverse`
for focused finalization measurements using an isolated native experiment.

Heap sampling runs approximately every millisecond and at phase boundaries.
It reports absolute `HeapAlloc`, including uncollected garbage, and can miss
short peaks. Sampling adds overhead; durations are diagnostic, not pure
throughput measurements. A GC runs before each iteration, never between phases.
The runner uses one iteration per fresh process for peak comparisons.

These synthetic measurements cover report ingestion, finalization, and streaming
export, excluding image scanning, downloads, vulnerability databases, Python
objects, and application output buffers. The JSON format is a benchmark fixture,
not a public export API. Retained result sizes are not construction peaks, and
reclaimable Go memory does not guarantee an immediate RSS reduction.

Keep captured output and comparisons under ignored
`explore_toolkit/experiments/<topic>/`, alongside environment and toolchain details.
Unit tests in `go/` assert report values and relationships, not index build order,
slab counts, allocation sizes, or retention strategies.

## Lifetime, cancellation, and scanner investigations

`measure.native_result_count()` reports native handle counts, optionally after
Python GC, using a compatible development build. Pass `library_path=` to observe
an isolated bridge library; counts belong to that library, not another loaded
copy. Sample it around any chosen workload, escaped view, cycle, or retained
task to investigate ownership without imposing a fixed handle-count guarantee.

Pass `images.RegistryPause(stage="manifest")` or `stage="layer"` as `pause=` to
`serve_registry()`. Its `entered` event signals a stalled response; `disconnected`
observes transport closure. Combine it with `asyncio.timeout`, task cancellation,
or cross-thread calls in an experiment. These transport observations are not
public API unit-test expectations.

For advisory lookups, `advisory_proxy()` accepts package-name or exact-PURL keys
mapped to sequences of OSV advisory dictionaries (including `id` and `modified`).
Pass its yielded values as `HTTPS_PROXY` and `SSL_CERT_FILE`, with
`NO_PROXY=127.0.0.1,localhost`, to a fresh worker via `processes.run_fresh()`.
The helper needs `openssl`; the unit suite needs no advisory service or registry.
Use `images.registry_resources(files)` for caller-chosen package/license inventory
and `reports.upstream_image()` for projected-report workloads. Keep credentials,
platform combinations, cancellation modes, and external image lists in the
experiment, rather than baking fixed regression matrices into the toolkit.

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
