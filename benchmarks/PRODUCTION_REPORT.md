# ABI 4 production reporting validation

Historical snapshot: public result import/export and materialization were
subsequently removed. Export timings and API-related tests below describe the
measurement revision. The current harness measures private native decoding,
retention, and traversal without Python result export.

Measured on 2026-09-16 with Python 3.13 and the production Go projection,
library MessagePack encoder, explicit msgspec schema, immutable facades, fix evidence,
and all forward/reverse packed indexes. Raw results are in
[production_results.json](production_results.json).

The fixture uses `tests/data/complete_response.json`, the same full-information
template as the historical batch experiment. Each successful image contains
2,000 package occurrences: 1,400 reference 140 shared advisories and 600 have
individual advisories. Package overlap and source-advisory overlap vary
independently. Source revisions, severity vectors and sources, timestamps,
locations, license facts, assessment facts, and package-specific fixes are
included in the production projection. This is a synthetic reporting workload,
not a measurement of real-world overlap prevalence.

| Workload | Retained Python MiB | Independent reports MiB | Acceptance |
| --- | ---: | ---: | --- |
| One image | 1.734 | 1.734 | Below 4 MiB |
| Ten fully overlapping images | 3.264 | 17.322 | Below 6 MiB |
| Ten partially overlapping images | 10.695 | 17.348 | Below 23 MiB |
| Ten disjoint images | 17.336 | 17.370 | Below 110% of independent |
| Ten images with large discarded descriptions | 3.264 | 17.322 | Same retained size as ordinary overlapping reports |

Independent reports use the same implementation and schema, not the removed
Pydantic path. The harness also measures alias-only sharing, differing per-image
assessments, and partial failures. Completed results retain zero C bytes.

The Python peak (including temporary wire bytes, eager decoding and relationship
index construction) was 4.01 MiB for one image, 12.76 MiB for ten overlapping
images, 25.52 MiB for partial overlap, and 40.84 MiB for disjoint images.
Results import/export only MessagePack; indexes are derived once in Python and
are not serialized. No expanded graph is cached.

## Simplification review

The first subagent review identified five changes, all implemented:

- Replace the handwritten reflective encoder with
  [vmihailenco/msgpack](https://pkg.go.dev/github.com/vmihailenco/msgpack/v5),
  streaming directly into the bounded C writer.
- Remove Go index construction and wire indexes; derive them once in Python.
- Remove JSON/dictionary result import, export, and expanded-report APIs.
- Replace the custom schema generator with explicit frozen msgspec records;
  typed literals validate versions and statuses during decoding.
- Pass the typed request directly inside Go instead of a JSON round trip.

Native MessagePack bytes and msgspec's typed records cover this schema without
custom [extension hooks](https://msgspec.dev/extending.html). Packed relationship
rows and lightweight views remain because they provide substantial memory gains.
A separate clean-slate subagent reviewed the resulting implementation and found
no further worthwhile simplifications or correctness blockers.

Compared with [the preserved pre-simplification measurements](before_simplification_results.json),
retained Python memory decreased by 0.01–0.10% across all workloads, while
Python peak memory decreased by 43–61%. Export timings are not directly
comparable: the previous benchmark exported JSON, whereas this one exports
MessagePack. These measurements support keeping the simpler implementation
without trading away retained-memory gains.

Go measurements sample the heap after adds and at finish, and report C writer
capacity alongside finish-time Go heap. They are checkpoint measurements, not
continuous Go peak coverage or a combined cross-runtime peak. Native construction
and encoding, and Python decode/traversal/export timings, are untraced. Python
retention and peak measurements use tracemalloc in separate fresh worker
processes. RSS includes runtime and allocator overhead and is reported separately.
The large-description case increases upstream/Go construction memory but does
not increase retained reporting memory. No acquisition/database scanning cost
is included in these fixture timings.

A separate real native-boundary stress run completed 64 independent offline
scans with 4 MiB discarded advisory descriptions in 0.99 seconds, with peak RSS
115.24 MiB. This is a stress observation, not a steady-state leak proof or a
scan-wide memory-savings claim.

Validation completed:

- 56 Python tests, including public-image, archive, registry/authentication,
  offline, license-policy, round-trip, malformed-wire and cleanup tests.
- Go projection/transport tests and the Go race detector.
- Ruff and strict mypy checks.
- Retained-memory gates for the final production schema.
- Source distribution and wheel builds.

Reproduce with:

```bash
uv run python -m benchmarks.production_store --output /tmp/production.json
uv run python -m benchmarks.native_memory --mode gated --scans 64 --details-mib 4
go -C go test -race ./...
uv run pytest
```
