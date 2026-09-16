# Result store experiments

Isolated prototypes supporting [the refactor plan](../../ABI_SERIALIZATION_FINDINGS.md).
These are research harnesses, not production implementations. They do not change
the library, its dependencies, or its ABI. Allocation-failure handling, full schema
coverage and public facade implementation belong to the production refactor.

The selected design is now one reporting projection, eagerly decoded into owned
Python data. Full-advisory transport/lifetime experiments below preserve evidence
for the broader alternative; they are not requirements of the selected plan.
`projection_review.py` reproduces the smaller eager-advisory retention probe. Run
it with the same isolated Python dependencies as the other probes. It starts with
full native bodies, then drops them, so it measures retained-memory feasibility,
not native projection peak or performance. It does not implement final per-CVE
fix evidence or public facades.

## Reproduce

From this directory, with Go 1.27.1:

```sh
go build -buildmode=c-shared -o lab.so .
```

From the repository root, use the project environment plus isolated probe packages:

```sh
uv run --with msgspec==0.21.1 --with flatbuffers==25.12.19 --with protobuf==7.36.1 python benchmarks/result_store/check_store_review.py
uv run --with msgspec==0.21.1 --with flatbuffers==25.12.19 --with protobuf==7.36.1 python benchmarks/result_store/run_gate_review.py
uv run --with msgspec==0.21.1 --with flatbuffers==25.12.19 --with protobuf==7.36.1 python benchmarks/result_store/check_batch_review.py
uv run --with msgspec==0.21.1 --with flatbuffers==25.12.19 --with protobuf==7.36.1 python benchmarks/result_store/run_batch_review.py
```

The gate runner writes `gate_results.json`. The broader suites are
`run_store_review.py`, `run_dense_review.py`, `run_final_review.py` and
`run_proto_review.py`; run them
sequentially. Each suite writes its corresponding `*_results.json`. The preserved
results were measured on Linux amd64 with Python 3.13.13, Pydantic 2.13.5 /
pydantic-core 2.46.5, msgspec 0.21.1 and Go 1.27.1. FlatBuffers Go is v25.2.10 and
Python is 25.12.19; Python protobuf is 7.36.1.

For individual probes, use the same `uv run --with ...` prefix:

```sh
PYOSV_FAST_EQUALITY=1 python benchmarks/result_store/store_review.py fanout_valid dense_direct pinned none
python benchmarks/result_store/retained_review.py dense_direct
python benchmarks/result_store/retained_review.py dense_eager
python benchmarks/result_store/worker_review.py unique
```

`pinned` is a positional handoff argument inherited by the runner. The
`dense_direct` and `dense_split` modes always return separate C-owned buffers;
they do not pin Go memory. The result's `retained_c_MiB` records their allocation.

## Files and modes

- `main.go`: current JSON/C-string path, native fixture loader, borrowed callback,
  pinned output and native-handle primitives.
- `store.go`: normalized packages/advisories with occurrence relationships;
  direct protobuf-to-MessagePack encoder; JSON, MessagePack, protobuf, native
  proxy and hybrid FlatBuffers alternatives.
- `dense.go`: shared occurrence contexts, packed relationship indexes,
  segmented output, direct C writer and record callbacks.
- `decoder_review.py`: fixture generator and experimental Pydantic-to-msgspec
  type conversion. This conversion is harness setup, not a proposed runtime
  dependency or production generation strategy.
- `store_review.py`: build/decode, selective access, repeated occurrence traversal,
  canonical advisory traversal, memory retention and release measurements.
- `check_store_review.py`: advisory and metadata parity, conflicting-content
  preservation, escaped-view ownership, read-only access and header-error cleanup.
- `retained_review.py`: ten retained results and final-view release.
- `worker_review.py`: worker startup, mapped-result delivery and aggregate-memory
  estimate. It includes fixture loading; its latency is not comparable directly
  with the result-only `build_ms` measurement.
- `run_proto_review.py`: fair dense/segmented protobuf-body comparison with the
  same metadata and direct C writer. `advisory_pb2_probe.py` contains pinned
  descriptor byte literals exported from the Go schema, avoiding runtime loading
  of descriptor-set message classes.
- `runtime_review.py`: five fresh-process measurements of minimal Python protobuf
  runtime/schema RSS overhead. `supplemental_results.json` preserves worker medians
  and the single-process ten-result ownership measurements.
- `batch.go`: incremental cross-image package/advisory/context interning, canonical
  body fingerprints with byte comparison, 1 MiB target C segments and private
  builder lifecycle. Discards upstream roots after each image; builder maps are
  released at finish. Oversized bodies get separate segments.
- `batch_review.py`: equivalent independent and batch result layouts, alias grouping,
  five packed reverse indexes, ownership, per-stage builder samples and retained
  memory measurements. Uses packed body addresses and on-demand views.
- `check_batch_review.py`: cross-image identities and alias-only grouping,
  conflicting bodies, per-image layers/license outcomes, presence versus findings,
  ordered partial/all failures, header-error cleanup and segment lifetimes.
- `run_batch_review.py` / `batch_results.json`: three fresh processes for each of
  ten cases (one-image baseline plus independent MessagePack, batch MessagePack
  and batch protobuf at three cross-image overlap levels).

`eager_pack` uses normal occurrence objects. `dense_eager` also shares context
records and packs relationships, but eagerly decodes advisories. `dense_direct`
uses that denser metadata and keeps advisory bodies as Raw views into an exact-size
C allocation. `dense_records` eagerly decodes one advisory per callback.
`raw` retains a monolithic encoded store; `raw_copy` detaches individual records.
`blob` encodes each advisory as a binary field decoded into a memoryview.
`dense_proto` keeps protobuf binary records as Raw views in an exact-size C arena,
then unwraps each requested record to a memoryview for protobuf parsing.

The FlatBuffers prototype provides direct ID/details fields and a MessagePack
remainder, avoiding duplication of those strings. It is a hybrid experiment,
not a generated FlatBuffers schema for every nested advisory field. The protobuf
prototype similarly uses a MessagePack envelope with protobuf advisory bodies.

## Workloads and limits

`fanout_valid` is the primary decision fixture: 2,000 distinct package occurrences,
with 1,400 referencing 140 shared advisories and 600 package-specific advisories.
Each shared advisory lists its ten affected packages. Group IDs, aliases,
analysis keys and PURLs agree with the advisory/package records.

`fanout_alias` gives the same first 1,400 packages shared CVE aliases in groups of
ten, but preserves 2,000 distinct advisory records with package-specific affected
data. This tests the boundary between a vulnerability group and an advisory.

`repeated` is an extreme sharing case; `unique` is a distinct-record stress case;
`mixed` repeats 2,000 distinct records ten times; `details` contains a 4 MiB text
field. The exploratory `unique`, `mixed` and `fanout` fixtures inherit group/alias
metadata from the base fixture. They are allocation stress tests, not semantically
complete scan examples. Use `fanout_valid` and `fanout_alias` for modeling decisions.

Suites use three fresh processes per case, with three untraced build timings in
each and a separate traced build/access pass. Setup loads the upstream Go result
before timing. Build timing includes normalization, native encoding, transfer and
the selected Python decoding. It excludes scanning, database work and fixture
loading. Retained results are measured after dropping the source Go graph and
forcing collection. Peak RSS includes setup and warm-up.

Python retained memory is tracemalloc's live allocation total. Add requested C
allocation bytes and live Go buffer/graph bytes where applicable. These totals
exclude interpreter/runtime baselines and allocator slack; they are not RSS.
Native protobuf internals are not measured by tracemalloc. The worker aggregate
estimate adds the waiting parent's RSS to the child's peak; it is not a sampled
simultaneous system-wide maximum.

The earlier single-image prototypes omit public facades, an eager summary table,
final grouping indexes and generated production codecs. Their costs must be
included when validating the refactor. Earlier suites predate some diagnostic
columns; the gate suite contains the final comparison and complete semantic fixtures.

## Batch measurement method

The batch suite is separate from the earlier timing methodology. Each image has
2,000 package occurrences and 740 advisory bodies: 70% of packages share records
in groups of ten, and 600 have individual records. Cross-image package overlap is
100%, 70% or 0%. At 70%, only the first 140 advisories are common across all images;
the ten-image union has 7,400 packages and 6,140 bodies. At full overlap, the union
has 2,000 packages and 740 bodies. At zero overlap it has 20,000 and 7,400.
All ten-image cases retain 20,000 occurrences. Different image metadata and
alternating license outcomes test that canonical packages do not absorb assessments.

Both independent and batch modes use identical Python grouping/index algorithms
and canonical native encoding. The batch is built incrementally in Go rather than
merging already decoded Python reports. The probe includes identity/alias summaries
and reverse indexes for package presence, vulnerability and noncompliance, and
advisory/group affected images. Complete public facades, production compact/full
summaries and applicable-fix projections remain outside this experiment.

Prepare fixtures one at a time on disk before tracing, and load one image at a
time. Drop source roots after every add. Fixed codec imports precede tracing;
`python_MiB + c_MiB` counts retained result allocations after builder release,
excluding codec baseline and allocator slack. Peak RSS includes setup and runtimes.
The batch protobuf probe parses bodies to extract IDs/aliases; the MessagePack
probe partially decodes them. Production header summaries avoid both operations.

`builder_live_go_MiB` is the largest sampled Go-heap increase after an add and GC;
it captures live builder maps and tables, not the active scan graph or total peak.
`largest_stage_live_MiB` adds C capacity and traced Python memory at those points;
it does not sample finish-time header/builder overlap. Neither replaces peak RSS.
`traced_build_index_ms` includes tracemalloc overhead: use it diagnostically, not
as an untraced performance claim. `canonical_traverse_ms` runs without tracing and
decodes each retained unique advisory once. No acquisition, database query or
real image scan runs in this harness.

Native batch exports are experimental: they lack production panic containment,
overflow validation, cancellation and exhaustive allocation-failure cleanup. The
tests exercise data modeling and ownership paths, not a completed public batch API.
