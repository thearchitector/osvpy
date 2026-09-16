import os
from pathlib import Path

os.environ["PYOSV_LAB_LIBRARY"] = str(Path(__file__).with_name("lab.so"))
os.environ["PYOSV_FAST_EQUALITY"] = "1"
import gc
import json
import sys
import tracemalloc
import weakref

import store_review as s

wire = s.msgspec.json.encode(s.fixture("unique"))
assert s.lib.lab_load(wire, len(wire)) == 0
del wire
mode = sys.argv[1]
owners = []


class TrackingOwner(s.Owner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        owners.append(weakref.ref(self))


s.Owner = TrackingOwner
tracemalloc.start()
results = [s.build(mode, "pinned", "none")[0] for _ in range(10)]
s.lib.store_drop_input()
gc.collect()
s.lib.lab_gc()
python_mib = tracemalloc.get_traced_memory()[0] / 2**20
c_mib = sum(len(r.buffer) for r in results if r.buffer is not None) / 2**20
escaped = results[0].root.advisories[0] if mode == "dense_direct" else results[0].get(0)
del results
gc.collect()
s.lib.lab_gc()
live_after_parent = sum(r() is not None for r in owners)
if mode == "dense_direct":
    assert s.decode_adv(escaped).id
del escaped
gc.collect()
s.lib.lab_gc()
assert not any(r() is not None for r in owners)
print(
    json.dumps(
        dict(
            mode=mode,
            results=10,
            python_MiB=python_mib,
            c_MiB=c_mib,
            combined_MiB=python_mib + c_mib,
            live_owners_after_parent_drop=live_after_parent,
            live_owners_after_last_view=0,
        )
    )
)
