# Architecture

The public API is asynchronous full-batch registry-image scanning. OSV-Scanner v2.6.0 remains
the scanning engine. Python, Cython 3.3.0, and private native ABI 6 ship together;
older ABIs and synchronous scan aliases are not supported.

## Ownership and lifecycle

Python snapshots image references, credentials, language selections, and license policies
into immutable JSON bytes when the coroutine executes. One executor job per
batch runs on the calling loop's default executor. There is no library executor,
per-image Python job, process-global decoder, or global scan lock.

Compiled calls link one bundled Go shared library; import checks its ABI version.
A controller lock protects each operation's cancellation flag and
published integer handle. Cancellation before publication prevents startup;
after publication it calls the signal-only native cancel entry point. The owner
detaches under this lock before releasing the handle. Joins and
disposal occur outside the lock.

The coroutine shields its completion future. On cancellation it
signals Go and continues shielding until the executor finishes, including through
repeated cancellation. It discards a completed result and re-raises
`CancelledError`. Consumers own deadlines through `asyncio.timeout()` or
`asyncio.wait_for()`, retaining asyncio's exception behavior. A foreign
thread must use `loop.call_soon_threadsafe(task.cancel)`.

Native create/start/wait/cancel/finish/release entry points use integer
`runtime/cgo.Handle` identifiers; no Go pointer crosses the ABI. Only cancellation
can overlap the owner's calls. Go cancellation signals a context and never joins.
Release joins workers before deleting the handle.

## Admission and reporting

Each operation starts at most `workers` fixed goroutines. One coordinator owns
the builder and all interners. Running plus completed-but-unmerged images never
exceeds `workers`. The coordinator projects each received result immediately,
drops the upstream graph, and merges compact facts in input order before admitting
another image. The next expected image projects directly into the batch. A slow
first image stops admission when its
window fills. Channel sends and receives unblock on cancellation.

Each worker owns its client factories for the operation. Every image gets fresh
plugin configuration. Scanner's gRPC client map has its own upstream mutex;
HTTP clients and transports support concurrent calls. The stateless SCALIBR
logger and discard slog handler are installed once. Never install Scanner's
mutable logger wrapper.

Ordinary failures occupy failed image slots. The library creates no deadlines
or per-image timers. Consumer cancellation stops admission and signals the
operation context. Cooperative cleanup can exceed a caller's asyncio deadline.

The batch normalizes packages, advisories, contexts, assessments, license facts,
and fixes into shared tables. Alias union/find remains global to the batch.
Comparable package keys and collision-safe structural equality preserve distinct
facts. Advisory group lookup and installed-version parsing are package-local.
No parsed-advisory cache or persistent package index is maintained.

## Native results and publication

Go owns the immutable normalized store. Occurrences and findings use compact
uint32 structs; relationship offsets and members are uint32 arrays. The builder
checks representational overflow. It retains existing collision-safe interning,
including internal JSON hashes, but retains no upstream scanner graph.

Finish transfers the store once to a separate result handle and clears operation
ownership, including for empty batches. Releasing the operation joins workers;
the completed result contains no worker, request, or credential state.

Cython views and sequences hold one shared owner, whose destruction releases the
result handle exactly once. There are no per-child handles or view caches.
Identity consists of that owner and the native record location. Slices return
tuples; collection order is deterministic. Constructors, pickling, and explicit
close are unavailable. Properties copy scalars on every access.

The private ABI dispatches explicitly by record and property identifiers, without
reflection. Strings are copied into caller-owned length-delimited buffers.
An undersized buffer reports the required size for retry. Unicode, embedded NULs,
and optional values survive unchanged; no persistent Go heap pointers escape.
Cython releases the GIL around operation creation, waiting, finishing, release,
and long-string copies. Tiny immutable reads do not depend on the GIL for safety.

CMake compiles the extension and Go shared library together, with package-relative
runtime linking on Linux and macOS. Wheels are interpreter-specific (3.13, 3.14,
3.14t); sources, Cython declarations, and stubs ship in distributions. There is no
dynamic loader, MessagePack result transport, Python decoder, or alternate backend.

## Coverage

`LanguageSelection` is a Flag with immutable plugin mapping. `None` preserves
the five existing artifact defaults. `NONE` disables those language plugins
while retaining OS extraction, annotations, and vulnerability matching. Family
unions include manifests and lockfiles. Base-image enrichment is always disabled;
default plugins remain enabled and transitive resolution remains disabled.

## Dependency patches

Builds copy the Go module into the build directory, run `go mod vendor`, and
apply the ordered unified diffs in `go/patches` with `git apply --check` followed
by `git apply`. The final command is `go build -mod=vendor`. Module versions and
`go.sum` pin the inputs; patch context must match or the build fails. Global
module caches are never edited. The `.patch` files ship in source distributions.
Patches add:

- A caller-context prepared-image entry point in Scanner.
- An indexed package-to-findings report join.
- Metadata-only protobuf conversion.
- Context-aware SCALIBR image preparation.

Upstream equivalents should replace these patches when dependencies
advance. Every dependency update requires re-evaluating globals, clients,
extractors, and cancellation propagation.

## Verification

Supported interpreter targets are CPython 3.13 and 3.14, and free-threaded
CPython 3.14. Free-threaded tests assert the build flag and
that imports and concurrency tests leave the GIL disabled. No scan lock or GIL
fallback may be used to pass them. Subinterpreters and shutdown that prevents
cleanup are outside the contract.

Tests force lifecycle races with barriers and events, verify ordered admission,
cleanup, reporting semantics, and concurrent
publication/readers. Installed wheels and source distributions are exercised.
Go race detection and a focused race-enabled native cancellation check complement
the unit tests. Expensive public-registry integration runs are manual CI jobs.
Performance experiments and broad upstream extractor audits are investigations,
not regression tests to rerun after subsequent implementation changes. Use
focused tests for the affected behavior.

The local test launcher (`python -m tests`) starts a controlled TLS advisory
service before pytest starts. This configures proxy and certificate settings
before the Go runtime snapshots its environment. Registry fixtures and advisory
responses exercise the compiled binding; tests never synthesize a Python result
store or replace native calls.

The cutover experiment in ignored `explore_toolkit/experiments/cython_cutover/`
preserves the baseline and raw measurements. Five fresh untraced processes per
shape/backend plus separate allocation passes show 49.3% lower live managed
bytes for mostly-unique records, 48.3% lower million-finding handoff peak RSS,
and 79.3% / 25.0% lower handoff-plus-traversal time on the two larger cases.
These are dedicated experiment gates, not timing-sensitive regression tests.
Repeated uncached scalar reads cost more; consumers should retain reused scalars.
Rollback is a release revert, not a second backend.

```bash
uv sync --group dev --group local
cd go
go mod vendor
git apply --check patches/*.patch
git apply patches/*.patch
go test -mod=vendor -race ./...
cd ..
uv run --no-sync python -m tests -m 'not integration'
uv run --no-sync ruff check src/osvpy tests explore_toolkit
uv run --no-sync mypy src/osvpy tests explore_toolkit
uv build
```

Caller-owned input mutation while snapshotting,
sharing one asyncio task between loops, and subinterpreters are unsupported.
Independent operations have independent worker budgets; callers must budget
aggregate memory and concurrency.

## Cython practice review

The binding follows Cython's [early binding guidance](https://cython.readthedocs.io/en/latest/src/userguide/early_binding_for_speed.html):
native access and view construction use typed `cdef` functions and extension
fields. Iteration, slicing, `count`, and `index` use `Py_ssize_t` loops and direct
internal reads. Python index conversion and slice normalization remain at the
boundary, including negative indices and arbitrarily large Python integers.
The Python-callable native scan entry rejects `None` for typed arguments before
dereferencing extension fields.

Following the [Cython optimization workflow](https://cython.readthedocs.io/en/latest/src/quickstart/cythonize.html),
generate annotated Cython HTML with
`uv run --no-project --with Cython==3.3.0 python -m cython -3 -a -I src -o /tmp/osvpy-native.c src/osvpy/_native.pyx`.
Inspect `/tmp/osvpy-native.html` for Python interaction before adding
type declarations or disabling checks. Bounds and exception checks remain
enabled; object-producing operations necessarily use Python's runtime. The
small constructor helper retains Cython's `tp_new` initialization and reuses an
immutable argument tuple; it does not allocate uninitialized extension objects.

The [parallelization tutorial](https://cython.readthedocs.io/en/latest/src/tutorial/parallelization.html)
applies to native computational loops that can run without Python interaction.
This binding boxes heterogeneous records into Python objects; it has no suitable
OpenMP kernel. Batch execution uses Python executor threads and Go workers.
Blocking waits, operation cleanup, and substantial native work release the GIL.

The [buffer guide](https://cython.readthedocs.io/en/latest/src/userguide/buffer.html)
describes typed access to buffer-exporting data, with memoryviews preferred for
new numerical code. Results here expose no persistent Go pointers or Python
buffer interface. Strings copy into call-local, length-delimited C buffers,
with required-size retry and `finally` cleanup for larger allocations. Memoryviews
would not improve this ownership boundary. Unicode, embedded NULs, and absent
values retain their distinct meanings.

The [free-threading suggestions](https://cython.readthedocs.io/en/latest/src/userguide/freethreading.html#opinionated-suggestions)
favor independent work and minimal shared mutation. Each operation owns its
state; published stores, views, and sequences are immutable, with no lazy caches.
Every traversal uses local loop state and temporary buffers. A Python lock
protects cancellation publication and detachment, including calls that release
the GIL. `freethreading_compatible=True` declares this design; installed-wheel
concurrency tests also verify that execution leaves the GIL disabled. Readers
should create separate iterators when traversing a shared sequence concurrently.

The build uses the [CMake/scikit-build pattern](https://cython.readthedocs.io/en/latest/src/userguide/compilation_scikit_build.html):
the selected Python interpreter runs Cython, a custom command tracks `.pyx` and
`.pxd` inputs, `Python_add_library(... MODULE WITH_SOABI ...)` builds the extension,
and installation places it beside its package-relative Go library. Cython is
pinned to 3.3.0 in isolated build requirements. Wheels carry interpreter-specific
tags, including the free-threaded ABI. Annotation generation uses Cython directly,
and race builds use `GOFLAGS=-race uv build --wheel` without custom CMake switches.

Release builds use CMake's compiler optimization defaults, with
[link-time optimization](https://cmake.org/cmake/help/latest/module/CheckIPOSupported.html)
and hidden symbols on the Cython extension. The build checks that the compiler
supports LTO. [Scikit-build strips installed extension binaries](https://scikit-build-core.readthedocs.io/en/latest/configuration/index.html#minimum-version-defaults);
the Go linker uses [`-s`, which also implies `-w`](https://pkg.go.dev/cmd/link),
to omit symbol and debug tables. Go retains its normal optimizer and portable CPU
baseline. This balances runtime speed and size without architecture-specific or
unsafe optimization flags. Dependency patching stays isolated in the build tree;
macOS install-name adjustment and signing keep the bundled library relocatable.

Build simplification verification (Linux, 2026-09-18): the wheel built from the
source distribution passed all 35 local tests on CPython 3.13 with the debug
allocator; the free-threaded 3.14 wheel also passed all 35 with the GIL disabled.
The `GOFLAGS=-race` wheel recorded race instrumentation in Go build metadata and
passed all 10 native cancellation tests. ELF inspection confirmed package-relative
loading and the exported Python module initializer. The extension changed from
204,200 to 204,192 bytes; the Go library remained 50,773,648 bytes, so total binary
size is essentially unchanged. These checks establish build correctness, not a
measured runtime speedup. macOS remains covered by CI, not this local verification.

Review verification (Linux, 2026-09-18): rebuilt and installed CPython 3.13 and
free-threaded 3.14 wheels; each passed all 35 local behavioral tests, with three
public-registry integration tests deselected. The 3.13 run used Python's debug
allocator; the 3.14t run asserted that the GIL stayed disabled. Generated HTML
was inspected for the changed traversal paths. Ruff, mypy, and whitespace checks
passed. This focused review did not repeat the earlier performance experiment or
macOS validation.
