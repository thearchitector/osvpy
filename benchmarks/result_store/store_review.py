"""Isolated result-representation experiment; does not change osvpy code."""

import ctypes as c
import gc
import json
import os
import resource
import statistics
import struct
import sys
import time
import tracemalloc
from pathlib import Path

from decoder_review import NativeResponse, convert_type, fixture, msgspec
from osvpy._generated import Advisory, GroupInfo, ImageOriginDetails, PackageInfo

AdvisoryModel = convert_type(Advisory)


class Occurrence(msgspec.Struct):
    source: int
    package: int
    advisories: tuple[int, ...]
    image_origin_details: convert_type(ImageOriginDetails) | None = None
    dependency_groups: tuple[str, ...] = ()
    groups: tuple[convert_type(GroupInfo), ...] = ()
    licenses: tuple[str, ...] = ()
    license_violations: tuple[str, ...] = ()


class Meta(msgspec.Struct):
    image: str
    metadata: object
    sources: tuple[object, ...]
    packages: tuple[convert_type(PackageInfo), ...]
    occurrences: tuple[Occurrence, ...]
    extras: object


Eager = msgspec.defstruct(
    "Eager", [("meta", Meta), ("advisories", tuple[AdvisoryModel, ...])]
)
Raw = msgspec.defstruct(
    "Raw", [("meta", Meta), ("advisories", tuple[msgspec.Raw, ...])]
)
Blob = msgspec.defstruct(
    "Blob", [("meta", Meta), ("advisories", tuple[memoryview, ...])]
)
decode_adv = msgspec.msgpack.Decoder(AdvisoryModel).decode


class IdOnly(msgspec.Struct):
    id: str = ""


class DetailsOnly(msgspec.Struct):
    details: str = ""


decode_id = msgspec.msgpack.Decoder(IdOnly).decode
decode_details = msgspec.msgpack.Decoder(DetailsOnly).decode
callback_type = c.CFUNCTYPE(None, c.c_void_p, c.c_size_t)
lib = c.CDLL(
    os.environ.get("PYOSV_LAB_LIBRARY", str(Path(__file__).with_name("lab.so")))
)
lib.lab_load.argtypes = [c.c_char_p, c.c_int]
lib.lab_load.restype = c.c_int
lib.store_build.argtypes = [
    c.c_int,
    c.c_int,
    c.POINTER(c.c_void_p),
    c.POINTER(c.c_size_t),
    callback_type,
]
lib.store_build.restype = c.c_size_t
lib.lab_unpin.argtypes = [c.c_size_t]
lib.lab_unpin.restype = None
lib.lab_free.argtypes = [c.c_void_p]
lib.lab_free.restype = None
lib.lab_report_release.argtypes = [c.c_size_t]
lib.lab_report_release.restype = None
lib.store_native_meta.argtypes = [c.c_size_t, callback_type]
lib.store_native_advisory.argtypes = [c.c_size_t, c.c_int, c.c_int, callback_type]
lib.store_native_count.argtypes = [c.c_size_t]
lib.store_native_count.restype = c.c_size_t
lib.store_native_ref.argtypes = [c.c_size_t, c.c_int, c.c_int]
lib.store_native_ref.restype = c.c_int
lib.store_descriptors.argtypes = [callback_type]
lib.lab_heap.restype = c.c_ulonglong
lib.lab_total_alloc.restype = c.c_ulonglong
if os.environ.get("PYOSV_FAST_EQUALITY"):
    lib.store_fast_equality.argtypes = [c.c_int]
    lib.store_fast_equality(1)


def view(ptr, n):
    return memoryview((c.c_ubyte * n).from_address(ptr)).cast("B").toreadonly()


class Owner:
    def __init__(self, ptr, n, handle, c_owned=False):
        self.ptr, self.n, self.handle, self.c_owned = ptr, n, handle, c_owned
        self.buffer = view(ptr, n)

    def __buffer__(self, flags):
        return self.buffer

    def __release_buffer__(self, buffer):
        pass

    def __del__(self):
        self.release_unexported()

    def release_unexported(self):
        if self.ptr is None:
            return
        if self.c_owned:
            lib.lab_free(self.ptr)
        else:
            lib.lab_unpin(self.handle)
        self.ptr = None


def meta_finish(meta):
    for field in ("metadata", "extras"):
        value = getattr(meta, field)
        if isinstance(value, bytes):
            setattr(meta, field, msgspec.json.decode(value))
    return meta


def proto_class():
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

    output = []

    @callback_type
    def sink(p, n):
        output.append(c.string_at(p, n))

    lib.store_descriptors(sink)
    descriptors = descriptor_pb2.FileDescriptorSet.FromString(output[0])
    pool = descriptor_pool.DescriptorPool()
    name = None
    for fd in descriptors.file:
        pool.Add(fd)
        for message in fd.message_type:
            if message.name == "Vulnerability":
                name = fd.package + ".Vulnerability"
    return message_factory.GetMessageClass(pool.FindMessageTypeByName(name))


class Result:
    def __init__(self, mode, root=None, buffer=None, handle=0, cache="none"):
        self.mode, self.root, self.buffer, self.handle = mode, root, buffer, handle
        self.cache_mode, self.cache = cache, {}
        if mode == "current":
            self.current_advisories = [
                a
                for source in root.result.sources
                for package in source.packages
                for a in package.vulnerabilities
            ]
            self.meta = CurrentMeta(len(self.current_advisories))
        elif mode == "native_only":
            self.meta = NativeMeta(handle)
        elif mode == "native":
            output = []

            @callback_type
            def sink(p, n):
                output.append(msgspec.msgpack.decode(view(p, n), type=Meta))

            lib.store_native_meta(handle, sink)
            self.meta = meta_finish(output[0])
        elif mode == "flat":
            import struct

            from flatbuffers.table import Table

            self.table = Table(buffer, struct.unpack_from("<I", buffer)[0])
            start = self.table.Vector(self.table.Offset(4))
            size = self.table.VectorLen(self.table.Offset(4))
            self.meta = meta_finish(
                msgspec.msgpack.decode(buffer[start : start + size], type=Meta)
            )
        elif mode.startswith("dense"):
            self.meta = DenseMetaView(meta_finish(root.meta))
        else:
            self.meta = meta_finish(root.meta)

    def __del__(self):
        if self.handle:
            lib.lab_report_release(self.handle)

    def flat_table(self, index):
        from flatbuffers.table import Table

        off = self.table.Vector(self.table.Offset(6)) + 4 * index
        return Table(self.buffer, self.table.Indirect(off))

    def get(self, index):
        if self.mode == "current":
            return self.current_advisories[index]
        if self.mode.startswith("eager") or self.mode in (
            "dense_eager",
            "dense_records",
        ):
            return self.root.advisories[index]
        if index in self.cache:
            return self.cache[index]
        if self.mode in ("native", "native_only"):
            output = []

            @callback_type
            def sink(p, n):
                output.append(decode_adv(view(p, n)))

            lib.store_native_advisory(self.handle, index, 2, sink)
            result = output[0]
        elif self.mode == "flat":
            t = self.flat_table(index)
            start = t.Vector(t.Offset(8))
            size = t.VectorLen(t.Offset(8))
            result = decode_adv(self.buffer[start : start + size])
            result.id = t.String(t.Pos + t.Offset(4)).decode()
            result.details = t.String(t.Pos + t.Offset(6)).decode()
        elif self.mode == "dense_proto":
            result = PROTO.FromString(
                msgspec.msgpack.decode(self.root.advisories[index], type=memoryview)
            )
        elif self.mode == "proto":
            result = PROTO.FromString(self.root.advisories[index])
        else:
            result = decode_adv(self.root.advisories[index])
        if self.cache_mode != "none":
            if self.cache_mode == "64" and len(self.cache) >= 64:
                self.cache.pop(next(iter(self.cache)))
            self.cache[index] = result
        return result

    def text(self, index, field="id"):
        if self.mode in ("native", "native_only"):
            output = []

            @callback_type
            def sink(p, n):
                output.append(c.string_at(p, n).decode())

            lib.store_native_advisory(
                self.handle, index, 0 if field == "id" else 1, sink
            )
            return output[0]
        if self.mode == "flat":
            t = self.flat_table(index)
            return t.String(t.Pos + t.Offset(4 if field == "id" else 6)).decode()
        if self.mode in (
            "raw",
            "raw_copy",
            "blob",
            "dense_raw",
            "dense_split",
            "dense_direct",
        ):
            return getattr(
                (decode_id if field == "id" else decode_details)(
                    self.root.advisories[index]
                ),
                field,
            )
        return getattr(self.get(index), field)


class NativeOccurrence:
    __slots__ = ("handle", "index")

    def __init__(self, handle, index):
        self.handle, self.index = handle, index

    @property
    def advisories(self):
        return (
            lib.store_native_ref(self.handle, self.index, i)
            for i in range(lib.store_native_ref(self.handle, self.index, -1))
        )


class NativeOccurrences:
    __slots__ = ("handle",)

    def __init__(self, handle):
        self.handle = handle

    def __len__(self):
        return lib.store_native_count(self.handle)

    def __iter__(self):
        return (NativeOccurrence(self.handle, i) for i in range(len(self)))


class NativeMeta:
    __slots__ = ("occurrences",)

    def __init__(self, handle):
        self.occurrences = NativeOccurrences(handle)


class CurrentOccurrence:
    __slots__ = ("advisories",)

    def __init__(self, index):
        self.advisories = (index,)


class CurrentOccurrences:
    __slots__ = ("count",)

    def __init__(self, count):
        self.count = count

    def __len__(self):
        return self.count

    def __iter__(self):
        return (CurrentOccurrence(i) for i in range(self.count))


class CurrentMeta:
    __slots__ = ("occurrences",)

    def __init__(self, count):
        self.occurrences = CurrentOccurrences(count)


class Context(msgspec.Struct):
    image_origin_details: convert_type(ImageOriginDetails) | None = None
    dependency_groups: tuple[str, ...] = ()
    groups: tuple[convert_type(GroupInfo), ...] = ()
    licenses: tuple[str, ...] = ()
    license_violations: tuple[str, ...] = ()


class DenseMeta(msgspec.Struct):
    image: str
    metadata: object
    sources: tuple[object, ...]
    packages: tuple[convert_type(PackageInfo), ...]
    contexts: tuple[Context, ...]
    occurrences: bytes
    refs: bytes
    extras: object


DenseEager = msgspec.defstruct(
    "DenseEager", [("meta", DenseMeta), ("advisories", tuple[AdvisoryModel, ...])]
)
DenseRaw = msgspec.defstruct(
    "DenseRaw", [("meta", DenseMeta), ("advisories", tuple[msgspec.Raw, ...])]
)


class DenseOccurrence:
    __slots__ = ("index", "meta")

    def __init__(self, meta, index):
        self.meta, self.index = meta, index

    @property
    def advisories(self):
        start, count = struct.unpack_from(
            "<II", self.meta.occurrences, self.index * 20 + 12
        )
        return (
            struct.unpack_from("<I", self.meta.refs, 4 * i)[0]
            for i in range(start, start + count)
        )


class DenseOccurrences:
    __slots__ = ("meta",)

    def __init__(self, meta):
        self.meta = meta

    def __len__(self):
        return len(self.meta.occurrences) // 20

    def __iter__(self):
        return (DenseOccurrence(self.meta, i) for i in range(len(self)))


class DenseMetaView:
    __slots__ = ("data", "occurrences")

    def __init__(self, meta):
        self.data = meta
        self.occurrences = DenseOccurrences(meta)


def build_dense(mode, cache):
    lib.store_dense.argtypes = [
        c.c_int,
        c.POINTER(c.c_void_p),
        c.POINTER(c.c_size_t),
        c.POINTER(c.c_void_p),
        c.POINTER(c.c_size_t),
    ]
    lib.store_dense.restype = c.c_size_t
    ptr, n, ap, an = c.c_void_p(), c.c_size_t(), c.c_void_p(), c.c_size_t()
    if mode == "dense_records":
        sinktype = c.CFUNCTYPE(None, c.c_void_p, c.c_size_t, c.c_int)
        lib.store_records.argtypes = [sinktype]
        records = []
        failure = []
        total = 0

        @sinktype
        def sink(p, n, kind):
            nonlocal total
            total += n
            try:
                records.append(
                    msgspec.msgpack.decode(
                        view(p, n), type=DenseMeta if kind == 0 else AdvisoryModel
                    )
                )
            except BaseException as e:
                failure.append(e)

        # Keep callbacks alive throughout the synchronous call.
        lib.store_records(sink)
        if failure:
            raise failure[0]
        root = DenseEager(records[0], tuple(records[1:]))
        return Result(mode, root, cache=cache), total
    split = mode in ("dense_split", "dense_direct", "dense_proto")
    if mode in ("dense_direct", "dense_proto"):
        fn = lib.store_dense_proto if mode == "dense_proto" else lib.store_dense_direct
        fn.argtypes = [
            c.POINTER(c.c_void_p),
            c.POINTER(c.c_size_t),
            c.POINTER(c.c_void_p),
            c.POINTER(c.c_size_t),
        ]
        fn(c.byref(ptr), c.byref(n), c.byref(ap), c.byref(an))
        handle = 0
    else:
        handle = lib.store_dense(
            int(split), c.byref(ptr), c.byref(n), c.byref(ap), c.byref(an)
        )
    if split:
        owner = Owner(ap.value, an.value, 0, True)
        try:
            meta = msgspec.msgpack.decode(view(ptr.value, n.value), type=DenseMeta)
        except BaseException:
            owner.release_unexported()
            raise
        finally:
            lib.lab_free(ptr.value)
        buffer = memoryview(owner)
        advisories = msgspec.msgpack.decode(buffer, type=tuple[msgspec.Raw, ...])
        root = DenseRaw(meta, advisories)
    else:
        owner = Owner(ptr.value, n.value, handle)
        buffer = memoryview(owner)
        root = msgspec.msgpack.decode(
            buffer, type=DenseEager if mode == "dense_eager" else DenseRaw
        )
        if mode == "dense_eager":
            buffer = None
    return Result(mode, root, buffer, cache=cache), n.value + an.value


mode_ids = {
    "eager_json": 0,
    "eager_pack": 1,
    "raw": 1,
    "raw_copy": 1,
    "blob": 2,
    "proto": 3,
    "native": 4,
    "native_only": 4,
    "flat": 5,
}


def build(mode, handoff, cache):
    if mode == "current":
        lib.lab_encode.argtypes = [c.c_int, c.POINTER(c.c_size_t)]
        lib.lab_encode.restype = c.c_void_p
        n = c.c_size_t()
        ptr = lib.lab_encode(0, c.byref(n))
        try:
            wire = c.string_at(ptr, n.value)
        finally:
            lib.lab_free(ptr)
        return Result(mode, NativeResponse.model_validate_json(wire)), n.value
    if mode.startswith("dense"):
        return build_dense(mode, cache)
    model = (
        Eager
        if mode.startswith("eager")
        else Raw
        if mode in ("raw", "raw_copy")
        else Blob
    )
    decoder = (msgspec.json if mode == "eager_json" else msgspec.msgpack).Decoder(model)
    output, failures = [], []

    @callback_type
    def sink(p, n):
        try:
            output.append(decoder.decode(view(p, n)))
        except BaseException as e:
            failures.append(e)

    ptr, n = c.c_void_p(), c.c_size_t()
    handle = lib.store_build(
        mode_ids[mode],
        {"callback": 0, "pinned": 1, "c": 2}[handoff],
        c.byref(ptr),
        c.byref(n),
        sink,
    )
    if failures:
        raise failures[0]
    if mode in ("native", "native_only"):
        return Result(mode, handle=handle, cache=cache), 0
    if handoff == "callback":
        assert mode.startswith("eager"), "borrowed views must not escape"
        root = output[0]
        buffer = None
    else:
        owner = Owner(ptr.value, n.value, handle, handoff == "c")
        buffer = memoryview(owner)
        root = None if mode == "flat" else decoder.decode(buffer)
        if mode == "raw_copy":
            root.advisories = tuple(raw.copy() for raw in root.advisories)
            buffer = None
        if mode.startswith("eager"):
            buffer = None
    return Result(mode, root, buffer, cache=cache), n.value


def rss():
    return int(Path("/proc/self/statm").read_text().split()[1]) * 4096 / 2**20


def main():
    global PROTO
    shape, mode, handoff, cache = sys.argv[1:5]
    if mode == "dense_proto":
        from advisory_pb2_probe import Advisory as PROTO
    elif mode == "proto":
        PROTO = proto_class()
    if shape in ("fanout", "fanout_valid", "fanout_alias"):
        data = fixture("unique")
        packages = data["result"]["results"][0]["packages"]
        if shape != "fanout":
            for i, p in enumerate(packages):
                a = p["vulnerabilities"][0]
                a["aliases"] = [f"CVE-2026-{10000 + i}"]
                a["affected"][0]["package"]["purl"] = f"pkg:deb/ubuntu/package-{i}@1.0"
                p["groups"][0]["ids"] = [a["id"]]
                p["groups"][0]["aliases"] = [a["id"], a["aliases"][0]]
                p["groups"][0]["experimental_analysis"] = {
                    a["id"]: {"called": True, "unimportant": False}
                }
        for start in range(0, 1400, 10):
            shared = packages[start]["vulnerabilities"][0]
            if shape != "fanout_alias":
                shared["affected"] = [
                    json.loads(json.dumps(p["vulnerabilities"][0]["affected"][0]))
                    for p in packages[start : start + 10]
                ]
            for p in packages[start : start + 10]:
                if shape == "fanout_alias":
                    a = p["vulnerabilities"][0]
                    a["aliases"] = shared["aliases"]
                    a["details"] = shared["details"]
                    p["groups"][0]["aliases"] = [a["id"], a["aliases"][0]]
                else:
                    p["vulnerabilities"] = [shared]
                    p["groups"][0]["ids"] = [shared["id"]]
                    p["groups"][0]["aliases"] = [shared["id"], shared["aliases"][0]]
                    if shape != "fanout":
                        p["groups"][0]["experimental_analysis"] = {
                            shared["id"]: {"called": True, "unimportant": False}
                        }
    elif shape == "mixed":
        data = fixture("unique")
        data["result"]["results"][0]["packages"] *= 10
    else:
        data = fixture(shape)
    wire = msgspec.json.encode(data)
    del data
    assert lib.lab_load(wire, len(wire)) == 0
    del wire
    gc.collect()
    lib.lab_gc()
    loaded_heap = lib.lab_heap()
    times = []
    native_alloc = []
    cold_traversals = []
    first_reads = []
    for _ in range(3):
        before = lib.lab_total_alloc()
        start = time.perf_counter()
        result, size = build(mode, handoff, cache)
        times.append(1000 * (time.perf_counter() - start))
        native_alloc.append(lib.lab_total_alloc() - before)
        assert len(result.meta.occurrences) == (
            20000
            if shape == "mixed"
            else 2000
            if shape in ("unique", "repeated", "fanout", "fanout_valid", "fanout_alias")
            else 1
        )
        start = time.perf_counter()
        result.text(0)
        first_reads.append(1000 * (time.perf_counter() - start))
        start = time.perf_counter()
        for occurrence in result.meta.occurrences:
            for index in occurrence.advisories:
                a = result.get(index)
                assert a.id
        cold_traversals.append(1000 * (time.perf_counter() - start))
        a = result.get(0)
        if mode not in ("proto", "dense_proto"):
            assert a.modified == "2026-02-02T00:00:00.123456789Z", a.modified
        else:
            assert a.modified.nanos == 123456789
        del a, result
    gc.collect()
    lib.lab_gc()
    tracemalloc.start()
    result, size = build(mode, handoff, cache)
    initial_python, peak_python = tracemalloc.get_traced_memory()
    lib.store_drop_input()
    gc.collect()
    lib.lab_gc()
    retained_go = lib.lab_heap()
    initial_rss = rss()
    start = time.perf_counter()
    first = result.text(0)
    selective_ms = 1000 * (time.perf_counter() - start)
    start = time.perf_counter()
    checksum = 0
    for occurrence in result.meta.occurrences:
        for index in occurrence.advisories:
            a = result.get(index)
            checksum += len(a.id) + len(a.details)
    del a
    traverse_ms = 1000 * (time.perf_counter() - start)
    # Timed traversal is repeated untraced below; tracing only measures retention.
    after_python, access_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    start = time.perf_counter()
    for occurrence in result.meta.occurrences:
        for index in occurrence.advisories:
            a = result.get(index)
            assert a.id
    del a
    hot_traverse = 1000 * (time.perf_counter() - start)
    count = (
        len(result.current_advisories)
        if mode == "current"
        else len(result.root.advisories)
        if result.root is not None
        else len({
            index
            for occurrence in result.meta.occurrences
            for index in occurrence.advisories
        })
    )
    start = time.perf_counter()
    for index in range(count):
        a = result.get(index)
        assert a.id
    del a
    canonical_traverse = 1000 * (time.perf_counter() - start)
    end_rss = rss()
    adv_wire_size = (
        len(result.buffer)
        if mode in ("dense_split", "dense_direct", "dense_proto")
        else 0
    )
    del result
    gc.collect()
    lib.lab_gc()
    released_go = lib.lab_heap()
    c_retained = 0
    # The C allocation is exact-size. Account for it separately from Go/tracemalloc.
    if mode in ("dense_split", "dense_direct", "dense_proto"):
        c_retained = adv_wire_size
    elif handoff == "c" and not mode.startswith("eager"):
        c_retained = size
    print(
        json.dumps(
            dict(
                shape=shape,
                mode=mode,
                handoff=handoff,
                cache=cache,
                wire_MiB=size / 2**20,
                retained_c_MiB=c_retained / 2**20,
                build_ms=statistics.median(times),
                first_read_ms=statistics.median(first_reads),
                cold_traverse_ms=statistics.median(cold_traversals),
                canonical_traverse_ms=canonical_traverse,
                native_alloc_MiB=statistics.median(native_alloc) / 2**20,
                initial_python_MiB=initial_python / 2**20,
                after_access_python_MiB=after_python / 2**20,
                python_peak_MiB=max(peak_python, access_peak) / 2**20,
                retained_go_MiB=retained_go / 2**20,
                go_released_MiB=(retained_go - released_go) / 2**20,
                initial_rss_MiB=initial_rss,
                after_access_rss_MiB=end_rss,
                max_rss_MiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
                traverse_ms=hot_traverse,
                traced_first_ms=selective_ms,
                checksum=checksum,
            )
        )
    )


if __name__ == "__main__":
    main()
