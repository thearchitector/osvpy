"""Cross-image interning, segmented ownership and image reverse-index experiment."""

import array
import ctypes as c
import gc
import json
import resource
import struct
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

import store_review as s


class Image(s.msgspec.Struct):
    name: str
    metadata: object
    extras: object
    sources: tuple[object, ...] | None
    start: int
    count: int
    error: str


Package = s.convert_type(s.PackageInfo)


class Header(s.msgspec.Struct):
    images: tuple[Image, ...]
    packages: tuple[Package, ...]
    contexts: tuple[s.Context, ...]
    rows: bytes
    refs: bytes
    bodies: bytes


class AdvisoryIdentity(s.msgspec.Struct):
    id: str
    aliases: tuple[str, ...] = ()


lib = s.lib
lib.batch_begin.argtypes = [c.c_int, c.c_int]
lib.batch_begin.restype = c.c_size_t
lib.batch_add.argtypes = [c.c_size_t]
lib.batch_add_error.argtypes = [c.c_size_t]
lib.batch_header.argtypes = [c.c_size_t, c.POINTER(c.c_void_p), c.POINTER(c.c_size_t)]
lib.batch_chunk_count.argtypes = [c.c_size_t]
lib.batch_chunk_count.restype = c.c_size_t
lib.batch_take_chunk.argtypes = [
    c.c_size_t,
    c.c_int,
    c.POINTER(c.c_void_p),
    c.POINTER(c.c_size_t),
]
lib.batch_c_bytes.argtypes = [c.c_size_t]
lib.batch_c_bytes.restype = c.c_size_t
lib.batch_release.argtypes = [c.c_size_t]


def image_fixture(image, overlap, n=2000):
    data = s.fixture("base")
    data["result"]["image"] = f"image-{image}"
    data["result"]["image_metadata"]["layer_metadata"][0]["diff_id"] = (
        f"sha256:layer-{image}"
    )
    template = data["result"]["results"][0]["packages"][0]
    shared = int(n * overlap)
    fanout = int(n * 0.7) // 10 * 10
    packages = []
    for i in range(n):
        p = json.loads(json.dumps(template))
        namespace = "shared" if i < shared else f"image{image}"
        p["package"]["name"] = f"{namespace}-package-{i}"
        p["license_violations"] = [] if image % 2 == 0 else ["GPL-3.0"]
        packages.append(p)
    for start in range(n):
        if start < fanout and start % 10:
            continue
        end = start + 10 if start < fanout else start + 1
        namespace = "shared" if end <= shared else f"image{image}"
        advisory = packages[start]["vulnerabilities"][0]
        advisory["id"] = f"OSV-{namespace}-{start}"
        advisory["aliases"] = [f"CVE-{namespace}-{start}"]
        affected = advisory["affected"][0]
        advisory["affected"] = []
        for p in packages[start:end]:
            a = json.loads(json.dumps(affected))
            a["package"]["name"] = p["package"]["name"]
            a["package"]["purl"] = f"pkg:deb/ubuntu/{p['package']['name']}@1.0"
            advisory["affected"].append(a)
            p["vulnerabilities"] = [advisory]
            p["groups"][0]["ids"] = [advisory["id"]]
            p["groups"][0]["aliases"] = [advisory["id"], *advisory["aliases"]]
            p["groups"][0]["experimental_analysis"] = {
                advisory["id"]: {"called": True, "unimportant": False}
            }
    data["result"]["results"][0]["packages"] = packages
    return data


def load(data):
    wire = s.msgspec.json.encode(data)
    assert lib.lab_load(wire, len(wire)) == 0


def packed(values):
    a = array.array("I", values)
    if sys.byteorder != "little":
        a.byteswap()
    return a.tobytes()


def reverse_index(count, edges):
    # Edges arrive in image order. A last-seen image removes duplicate memberships
    # without allocating a Python set/list for each entity.
    last = [-1] * count
    counts = [0] * count
    pairs = array.array("I")
    for target, image in edges:
        if last[target] == image:
            continue
        last[target] = image
        counts[target] += 1
        pairs.extend((target, image))
    offsets = [0]
    for n in counts:
        offsets.append(offsets[-1] + n)
    cursors = offsets[:-1].copy()
    members = array.array("I", [0]) * offsets[-1]
    for i in range(0, len(pairs), 2):
        target, image = pairs[i : i + 2]
        members[cursors[target]] = image
        cursors[target] += 1
    return packed(offsets), packed(members)


class Batch:
    def __init__(self, header, chunks, protobuf=False):
        self.header, self.chunks, self.protobuf = header, chunks, protobuf
        for image in header.images:
            if image.error:
                continue
            s.meta_finish(image)
        self.identities = []
        if protobuf:
            from advisory_pb2_probe import Advisory

            self.proto = Advisory
        for i in range(len(header.bodies) // 12):
            if protobuf:
                record = self.proto.FromString(self.raw(i))
                identity = AdvisoryIdentity(record.id, tuple(record.aliases))
            else:
                identity = s.msgspec.msgpack.decode(self.raw(i), type=AdvisoryIdentity)
            self.identities.append(identity)
        self.identities = tuple(self.identities)
        parent = {}

        def root(k):
            parent.setdefault(k, k)
            while parent[k] != k:
                parent[k] = parent[parent[k]]
                k = parent[k]
            return k

        def order(k):
            return (not k.startswith("CVE-"), k)

        for a in self.identities:
            for alias in a.aliases:
                x, y = root(a.id), root(alias)
                if x != y:
                    if order(x) > order(y):
                        x, y = y, x
                    parent[y] = x
        groups = {}
        advisory_groups = []
        for a in self.identities:
            name = root(a.id)
            if name not in groups:
                groups[name] = len(groups)
            advisory_groups.append(groups[name])
        self.groups = tuple(groups)
        self.advisory_groups = packed(advisory_groups)
        pcount = len(header.packages)
        acount = len(self.identities)
        self.indexes = {}
        for kind, count in [
            ("present", pcount),
            ("vulnerable", pcount),
            ("noncompliant", pcount),
            ("advisory", acount),
            ("vulnerability", len(groups)),
        ]:
            self.indexes[kind] = reverse_index(count, self.edges(kind, advisory_groups))

    def raw(self, index):
        chunk, off, n = struct.unpack_from("<III", self.header.bodies, index * 12)
        return self.chunks[chunk][off : off + n]

    def advisory(self, index):
        raw = self.raw(index)
        return self.proto.FromString(raw) if self.protobuf else s.decode_adv(raw)

    def rows(self):
        return struct.iter_unpack("<IIIIII", self.header.rows)

    def edges(self, kind, groups):
        for image, source, package, context, start, count in self.rows():
            if (
                kind == "present"
                or kind == "vulnerable"
                and count
                or kind == "noncompliant"
                and self.header.contexts[context].license_violations
            ):
                yield package, image
            elif kind in ("advisory", "vulnerability"):
                for i in range(start, start + count):
                    a = struct.unpack_from("<I", self.header.refs, i * 4)[0]
                    yield (groups[a] if kind == "vulnerability" else a), image

    def images_for(self, kind, index):
        offsets, members = self.indexes[kind]
        start, end = struct.unpack_from("<II", offsets, index * 4)
        return tuple(
            struct.unpack_from("<I", members, i * 4)[0] for i in range(start, end)
        )

    def c_bytes(self):
        return sum(len(x) for x in self.chunks)


def finish(handle, protobuf=False):
    p, n = c.c_void_p(), c.c_size_t()
    try:
        lib.batch_header(handle, c.byref(p), c.byref(n))
        try:
            header = s.msgspec.msgpack.decode(s.view(p.value, n.value), type=Header)
        finally:
            lib.lab_free(p)
        chunks = []
        for i in range(lib.batch_chunk_count(handle)):
            lib.batch_take_chunk(handle, i, c.byref(p), c.byref(n))
            chunks.append(memoryview(s.Owner(p.value, n.value, 0, True)))
    finally:
        lib.batch_release(handle)
    return Batch(header, tuple(chunks), protobuf)


def measure(count, overlap, mode, protobuf=False):
    # Measure per-result retention separately from fixed codec/runtime imports.
    # Fresh-process RSS still includes this runtime; runtime_results.json measures
    # its incremental residency independently.
    shared = mode == "batch"
    handles = []
    results = []
    build_ms = 0
    largest_builder = 0
    peak_retained = 0
    handle = lib.batch_begin(1, int(protobuf)) if shared else None
    # Prepare fixtures one at a time on disk, outside tracing/timing. Do not keep
    # all input graphs resident and mistake fixture setup for batch execution.
    directory = tempfile.TemporaryDirectory()
    fixturefiles = []
    for i in range(count):
        p = Path(directory.name) / str(i)
        p.write_bytes(s.msgspec.json.encode(image_fixture(i, overlap)))
        fixturefiles.append(p)
    gc.collect()
    lib.lab_gc()
    base_go = lib.lab_heap()
    tracemalloc.start()
    for i in range(count):
        if not shared:
            handle = lib.batch_begin(1, int(protobuf))
        wire = fixturefiles[i].read_bytes()
        assert lib.lab_load(wire, len(wire)) == 0
        del wire
        start = time.perf_counter()
        lib.batch_add(handle)
        build_ms += (time.perf_counter() - start) * 1000
        lib.lab_gc()
        largest_builder = max(largest_builder, (lib.lab_heap() - base_go) / 2**20)
        c_live = lib.batch_c_bytes(handle) + sum(x.c_bytes() for x in results)
        peak_retained = max(
            peak_retained,
            c_live / 2**20
            + max(0, lib.lab_heap() - base_go) / 2**20
            + tracemalloc.get_traced_memory()[0] / 2**20,
        )
        if not shared:
            start = time.perf_counter()
            results.append(finish(handle, protobuf))
            build_ms += (time.perf_counter() - start) * 1000
    if shared:
        start = time.perf_counter()
        results.append(finish(handle, protobuf))
        build_ms += (time.perf_counter() - start) * 1000
    gc.collect()
    lib.lab_gc()
    python, peak_python = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    c_total = sum(r.c_bytes() for r in results)
    counts = {
        "packages": sum(len(r.header.packages) for r in results),
        "advisories": sum(len(r.identities) for r in results),
        "groups": sum(len(r.groups) for r in results),
        "occurrences": sum(len(r.header.rows) // 24 for r in results),
    }
    start = time.perf_counter()
    for r in results:
        for i in range(len(r.identities)):
            a = r.advisory(i)
            assert a.id
    del a
    access_ms = (time.perf_counter() - start) * 1000
    checksum = sum(
        len(r.images_for("vulnerability", i))
        for r in results
        for i in range(len(r.groups))
    )
    row = dict(
        images=count,
        overlap=overlap,
        mode=mode,
        codec="protobuf" if protobuf else "msgpack",
        python_MiB=python / 2**20,
        c_MiB=c_total / 2**20,
        retained_MiB=(python + c_total) / 2**20,
        builder_live_go_MiB=largest_builder,
        largest_stage_live_MiB=peak_retained,
        python_peak_MiB=peak_python / 2**20,
        max_rss_MiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
        traced_build_index_ms=build_ms,
        canonical_traverse_ms=access_ms,
        reverse_index_bytes=sum(
            sum(len(v) for v in pair) for r in results for pair in r.indexes.values()
        ),
        chunks=sum(len(r.chunks) for r in results),
        group_image_memberships=checksum,
        **counts,
    )
    del results
    gc.collect()
    lib.lab_gc()
    directory.cleanup()
    return row


if __name__ == "__main__":
    n, overlap, mode = sys.argv[1:4]
    print(
        json.dumps(
            measure(
                int(n),
                float(overlap),
                mode,
                len(sys.argv) > 4 and sys.argv[4] == "protobuf",
            )
        )
    )
