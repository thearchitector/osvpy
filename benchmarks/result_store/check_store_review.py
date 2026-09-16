import gc
import os
import weakref
from pathlib import Path

os.environ["PYOSV_LAB_LIBRARY"] = str(Path(__file__).with_name("lab.so"))
os.environ["PYOSV_FAST_EQUALITY"] = "1"
import store_review as s

wire = s.msgspec.json.encode(s.fixture("unique"))
assert s.lib.lab_load(wire, len(wire)) == 0
baseline, _ = s.build("eager_json", "pinned", "none")
for mode in [
    "eager_pack",
    "raw",
    "raw_copy",
    "blob",
    "flat",
    "native",
    "native_only",
    "dense_eager",
    "dense_raw",
    "dense_split",
    "dense_direct",
    "dense_records",
]:
    result, _ = s.build(mode, "pinned", "none")
    for index in [0, 1, 1999]:
        assert s.msgspec.to_builtins(result.get(index)) == s.msgspec.to_builtins(
            baseline.get(index)
        ), mode
    assert len(result.meta.occurrences) == 2000
    assert result.text(0) == baseline.text(0)
    if mode.startswith("dense"):
        meta = result.meta.data
        for field in ("image", "metadata", "sources", "packages", "extras"):
            assert s.msgspec.to_builtins(getattr(meta, field)) == s.msgspec.to_builtins(
                getattr(baseline.meta, field)
            ), (mode, field)
        for index in [0, 1999]:
            source, package, context, start, count = s.struct.unpack_from(
                "<IIIII", meta.occurrences, index * 20
            )
            b = baseline.meta.occurrences[index]
            assert (source, package) == (b.source, b.package)
            ctx = meta.contexts[context]
            for field in (
                "image_origin_details",
                "dependency_groups",
                "groups",
                "licenses",
                "license_violations",
            ):
                assert s.msgspec.to_builtins(
                    getattr(ctx, field)
                ) == s.msgspec.to_builtins(getattr(b, field)), (mode, field)
            assert (
                tuple(
                    s.struct.unpack_from("<I", meta.refs, 4 * i)[0]
                    for i in range(start, start + count)
                )
                == b.advisories
            )
    print(mode, "advisory field parity passed")
    del result


class TrackingOwner(s.Owner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        global owner
        owner = weakref.ref(self)


s.Owner = TrackingOwner
result, _ = s.build("dense_direct", "pinned", "none")
escaped = result.root.advisories[0]
buffer = result.buffer
del result, buffer
gc.collect()
s.lib.lab_gc()
assert owner() is not None
assert s.decode_adv(escaped).modified == "2026-02-02T00:00:00.123456789Z"
assert memoryview(escaped).readonly
del escaped
gc.collect()
s.lib.lab_gc()
assert owner() is None
print(
    "escaped Raw keeps exact C owner alive, remains read-only, and releases owner after final view"
)

# Alias equality is insufficient to merge conflicting advisory records.
data = s.fixture("unique")
packages = data["result"]["results"][0]["packages"][:2]
data["result"]["results"][0]["packages"] = packages
packages[1]["vulnerabilities"][0]["id"] = packages[0]["vulnerabilities"][0]["id"]
wire = s.msgspec.json.encode(data)
assert s.lib.lab_load(wire, len(wire)) == 0
result, _ = s.build("dense_split", "pinned", "none")
assert len(result.root.advisories) == 2
assert result.get(0).details != result.get(1).details
print("same ID and timestamp with conflicting content remains two advisory records")


class InvalidHeader(s.msgspec.Struct):
    missing_required_header_field: int


saved = s.DenseMeta
s.DenseMeta = InvalidHeader
try:
    s.build("dense_direct", "pinned", "none")
except s.msgspec.ValidationError:
    assert owner() is None or owner().ptr is None
else:
    raise AssertionError("expected header validation failure")
finally:
    s.DenseMeta = saved
print("header decode failure releases the unexported advisory allocation")

from advisory_pb2_probe import Advisory as ProtoAdvisory
from google.protobuf.json_format import MessageToDict

s.PROTO = ProtoAdvisory
data = s.fixture("unique")
wire = s.msgspec.json.encode(data)
assert s.lib.lab_load(wire, len(wire)) == 0
result, _ = s.build("dense_proto", "pinned", "none")
for index in [0, 1, 1999]:
    expected = data["result"]["results"][0]["packages"][index]["vulnerabilities"][0]
    assert MessageToDict(result.get(index)) == expected
print("segmented protobuf advisory fields match the source fixture")
