# Architecture

This document describes the library's design contract and the reasons for its
main implementation choices. It is reference material for agents changing the
code.

## Scope and workload

The library exposes asynchronous, full-batch container-image scanning. OSV-Scanner
is the scanning engine; Python and Cython provide the public API; Go owns scanning
coordination, normalization, storage, and the private native ABI.

The workload has two phases:

1. **Ingestion:** many images are scanned and projected into one report. This is
   append-heavy and memory-sensitive.
2. **Immutable access:** the completed report may traverse essentially every
   record and relationship path. Relationship indexes are therefore retained for
   predictable keyed traversal. Replacing them with repeated scans would trade
   final memory for repeated large-table work and could make reverse traversals
   quadratic.

## Ownership and lifecycle

Python snapshots request data into immutable JSON bytes when the scan coroutine
executes. One executor job runs the batch; the library does not create a second
Python executor, a process-global decoder, or a global scan lock.

The native boundary passes integer `runtime/cgo.Handle` values. Go pointers never
cross the ABI. A controller lock protects cancellation state and handle
publication. Cancellation signals the Go context; it does not join workers while
holding the lock. Release joins workers before deleting the operation handle.

The coroutine shields completion and continues cleanup after caller cancellation.
The completed result owns the immutable report through one shared owner. Cython
views and sequences retain that owner; child views do not have independent native
handles or caches. Releasing the final owner releases the Go result exactly once.

## Admission and projection

One coordinator owns the builder and all batch interners. At most `workers`
goroutines are active. Running plus completed-but-unmerged images is bounded by
that worker window. Results merge in input order, so publication is deterministic.

Workers project scanner output into library-owned facts immediately. The upstream
scanner graph is then eligible for collection. The report never retains scanner
protobuf catalogs, parsed database records, plugin configuration, credentials, or
worker state.

Ordinary scan failures occupy an image slot and become failed image records.
Consumer cancellation stops admission and signals the operation context. The
library does not impose per-image deadlines; callers own deadlines with
`asyncio.timeout()` or `asyncio.wait_for()`.

## Store model

The frozen store is schema-specific, not a generic graph. Direct N:1 relationships
are compact integer columns. Multi-valued relationships use offset/member indexes.
This avoids per-edge objects and keeps traversal representation predictable.

The principal tables are:

- images;
- normalized packages, contexts, licenses, assessments, fixes, and advisories;
- vulnerability groups formed by batch-wide alias union/find;
- occurrence rows linking image, package, context, and license;
- finding rows linking occurrence, advisory, fix, and assessment;
- an advisory-to-vulnerability array.

Finding vulnerability identity is derived through the advisory-to-vulnerability
array. It is not duplicated in every finding row.

All row IDs are checked against `uint32` limits. Rows are immutable after
finalization. The public ABI translates IDs into views and copies scalar values
on access.

## Slab storage and peak-memory invariants

Large retained tables use fixed-size slabs. Appending allocates a new bounded slab
when the previous slab fills; it never reallocates and copies the entire table.
Row addresses remain stable while the table grows. This applies to normalized
tables, occurrences, findings, string/payload arrays, and relationship arrays.

Index construction uses count, prefix-sum, fill, sort, and compaction. Membership
arrays are compacted in place inside segmented storage. Finalization truncates
unused slabs instead of cloning the live prefix into a second full allocation.
At most one partially used slab remains for a compacted membership array.

The finalization order is:

1. resolve alias groups and assign vulnerability IDs;
2. build the advisory-to-vulnerability array;
3. clear builder-only maps, collision chains, and scratch state;
4. transfer the report tables into the result;
5. build frozen relationship indexes from the transferred tables.

The ordering prevents ingestion maps from remaining live while index memory is
being allocated. It does not promise immediate RSS reduction or force a garbage
collection.

## Interning and compact payloads

Interning uses typed comparable keys for fixed records. Variable-length payloads
use compact string IDs and spans into shared word arrays. Fingerprints select a
collision chain; complete typed equality checks preserve correctness on collision.
No JSON serialization, reflection-based equality, SHA-256 allocation path, or
per-hash slice of candidate IDs is required.

Repeated strings are stored once where practical. Optional strings use zero as an
absent ID. Optional booleans use a validity/value tag. Status values use compact
enums. Lists use `(start,count)` spans; nil and empty spans remain distinct.
Severities and references are stored as packed string-ID sequences.

Scanner projection structs may remain convenient pointer/slice-bearing values
while transient. Normalized tables retained by the completed store use compact
fields. Small per-image metadata and diagnostics remain attached to image records
because they are independently exposed by the public API.

## Frozen relationship indexes

The store materializes all declared relationship indexes because immutable access
may traverse every path. Indexes contain only uint32 offsets and members;
contiguous relationships retain offsets without a member allocation.

The index set includes image, occurrence, package, advisory, vulnerability, and
finding paths. Reverse indexes intentionally remain available for package,
advisory, and vulnerability traversals. They must not be removed solely because
some individual reads are infrequent. Index reduction would require evidence that
the actual workload is sparse enough to justify repeated scans or a new iterator
contract.

## Native ABI

The private ABI dispatches by numeric record and property identifiers. It uses no
reflection. String reads are length-delimited copies into caller-owned buffers;
undersized buffers report the required size for retry. Embedded NULs, Unicode, and
absent values remain distinguishable.

The ABI version is checked at import. No persistent Go heap pointer escapes to
Python. Cython releases the GIL around native create, wait, finish, release, and
long-string operations.

## Concurrency and Cython rules

Each operation owns its workers, clients, cancellation state, and report builder.
Published reports and all views are immutable. Shared access requires no lazy
cache or mutable view state. Free-threaded builds must remain free-threaded; a
global lock or GIL fallback is not part of the design.

Cython uses typed loops and local state for iteration, slicing, `count`, and
`index`. Slices return tuples. Constructors, pickling, and explicit close are
unavailable. A view's identity is the shared owner plus native record location.

## Build and dependency boundaries

CMake builds the Cython extension and one bundled Go shared library together.
Go modules are copied into a build directory, vendored, and patched there; the
source checkout and global module caches are never modified. Package-relative
runtime linking keeps the bundled library relocatable on Linux and macOS.

Supported interpreters are CPython 3.13, CPython 3.14, and free-threaded CPython
3.14t. No alternate backend, dynamic result decoder, MessagePack transport, or
synchronous scan alias exists.

## Required invariants for changes

Changes must preserve:

- stable row IDs and checked `uint32` overflow behavior;
- no full-size backing-array replacement during ingestion;
- no full-size membership clone during index finalization;
- release of builder-only state before index allocation;
- deterministic input-order image publication;
- no upstream scanner graph retained by a completed report;
- distinct nil, empty, false, and zero-valued optional semantics;
- one native owner for each completed report;
- cancellation cleanup after caller-task cancellation;
- schema-specific compact relationships instead of generic edge objects.

## Verification

Focused Go tests cover ordered admission, cancellation, alias grouping, compact
payload round trips, hash-collision equality, slab growth, index compaction, and
all materialized relationships. Run:

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

Performance experiments are diagnostics, not timing-sensitive regression tests.
Measure peak RSS when changing slab size, payload packing, or index construction.
