"""Verify batch identity, per-image assessment, reverse views and ownership."""

import gc
import weakref

import batch_review as b

owners = []


class TrackingOwner(b.s.Owner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        owners.append(weakref.ref(self))


b.s.Owner = TrackingOwner

handle = b.lib.batch_begin(1, 0)
for image in range(2):
    b.load(b.image_fixture(image, 1.0, 20))
    b.lib.batch_add(handle)
    if image == 0:
        b.lib.batch_add_error(handle)
batch = b.finish(handle)
assert len(batch.header.images) == 3
assert batch.header.images[1].error
assert batch.header.images[1].count == 0
assert batch.header.images[0].name == "image-0"
assert batch.header.images[2].name == "image-1"
assert len(batch.header.packages) == 20
assert len(batch.identities) == 11
assert len(batch.header.rows) // 24 == 40
assert batch.images_for("present", 0) == (0, 2)
assert batch.images_for("vulnerable", 0) == (0, 2)
assert batch.images_for("noncompliant", 0) == (2,)
assert batch.images_for("vulnerability", 0) == (0, 2)
assert (
    batch.header.images[0].extras["image_metadata"]["layer_metadata"][0]["diff_id"]
    == "sha256:layer-0"
)
assert (
    batch.header.images[2].extras["image_metadata"]["layer_metadata"][0]["diff_id"]
    == "sha256:layer-1"
)
print(
    "cross-image entity sharing, per-image layers and license outcomes, ordered partial failures and deduplicated reverse memberships passed"
)
escaped = b.s.msgspec.Raw(batch.raw(0))
del batch
gc.collect()
b.lib.lab_gc()
assert any(ref() is not None for ref in owners)
assert b.s.decode_adv(escaped).id == "OSV-shared-0"
assert memoryview(escaped).readonly
del escaped
gc.collect()
b.lib.lab_gc()
assert not any(ref() is not None for ref in owners)
print(
    "escaped batch advisory keeps only its segment owner alive and releases it after final view"
)

handle = b.lib.batch_begin(1, 0)
for image in range(2):
    data = b.image_fixture(image, 1.0, 20)
    if image:
        advisory = data["result"]["results"][0]["packages"][0]["vulnerabilities"][0]
        advisory["details"] = "conflicting content, same ID and timestamp"
        data["result"]["results"][0]["packages"][0]["package"]["version"] = "2.0"
    b.load(data)
    b.lib.batch_add(handle)
batch = b.finish(handle)
assert len(batch.header.packages) == 21
assert len(batch.identities) == 12
assert len(batch.groups) == 11
assert batch.images_for("vulnerability", 0) == (0, 1)
print(
    "package versions and conflicting advisory bodies remain distinct while their CVE group is shared"
)
del batch
gc.collect()

handle = b.lib.batch_begin(1, 0)
for image in range(2):
    data = b.image_fixture(image, 1.0, 20)
    if image:
        seen = set()
        for p in data["result"]["results"][0]["packages"]:
            advisory = p["vulnerabilities"][0]
            if id(advisory) not in seen:
                seen.add(id(advisory))
                advisory["id"] = "OTHER-" + advisory["id"]
            p["groups"][0]["ids"] = [advisory["id"]]
            p["groups"][0]["aliases"] = [advisory["id"], *advisory["aliases"]]
            p["groups"][0]["experimental_analysis"] = {
                advisory["id"]: {"called": True, "unimportant": False}
            }
    b.load(data)
    b.lib.batch_add(handle)
batch = b.finish(handle)
assert len(batch.identities) == 22
assert len(batch.groups) == 11
assert batch.images_for("vulnerability", 0) == (0, 1)
assert batch.images_for("advisory", 0) == (0,)
assert batch.images_for("advisory", 11) == (1,)
del batch
gc.collect()
print(
    "distinct source advisories share cross-image CVE groups without merging bodies or advisory memberships"
)

handle = b.lib.batch_begin(1, 0)
data = b.image_fixture(0, 1.0, 20)
packages = data["result"]["results"][0]["packages"]
packages[0]["vulnerabilities"] = []
packages[1]["vulnerabilities"].append(packages[-1]["vulnerabilities"][0])
b.load(data)
b.lib.batch_add(handle)
batch = b.finish(handle)
assert batch.images_for("present", 0) == (0,)
assert batch.images_for("vulnerable", 0) == ()
assert batch.images_for("advisory", 10) == (0,)
assert len(batch.header.refs) // 4 == 20
print(
    "presence is separate from vulnerability, multiple findings preserve occurrences, reverse images do not duplicate"
)
del batch
gc.collect()

handle = b.lib.batch_begin(1, 0)
data = b.image_fixture(0, 1.0, 20)
for p in data["result"]["results"][0]["packages"]:
    p["vulnerabilities"][0]["details"] = "x" * (1100 * 1024)
b.load(data)
b.lib.batch_add(handle)
batch = b.finish(handle)
assert len(batch.chunks) > 1
escaped = b.s.msgspec.Raw(batch.raw(0))
del batch
gc.collect()
b.lib.lab_gc()
assert sum(ref() is not None for ref in owners) == 1
assert len(b.s.decode_adv(escaped).details) == 1100 * 1024
del escaped
gc.collect()
b.lib.lab_gc()
assert not any(ref() is not None for ref in owners)
print(
    "large records use separate segments; one escaped record does not retain the whole batch"
)

handle = b.lib.batch_begin(1, 0)
b.lib.batch_add_error(handle)
batch = b.finish(handle)
assert len(batch.header.images) == 1
assert batch.header.images[0].error
assert not batch.header.packages
assert not batch.chunks
assert not batch.groups
del batch
print("all-failed batch has valid empty entity tables and no body allocation")

handle = b.lib.batch_begin(1, 0)
b.load(b.image_fixture(0, 1.0, 20))
b.lib.batch_add(handle)
original_header = b.Header
original_release = b.lib.batch_release
released = []


def release(handle):
    released.append(handle)
    original_release(handle)


b.Header = int
b.lib.batch_release = release
try:
    try:
        b.finish(handle)
    except b.s.msgspec.ValidationError:
        pass
    else:
        raise AssertionError("invalid header accepted")
finally:
    b.Header = original_header
    b.lib.batch_release = original_release
assert released == [handle]
print("header validation failure releases the builder and every unclaimed segment")
