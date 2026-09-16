"""Exploratory retention of small eager advisory projections, not native projection.

Uses the batch harness's full native input before dropping bodies. This measures
retention only; it cannot establish production construction peak or speed. Final
finding/fix projections and public facades are outside this experiment.
"""

import json

import batch_review as b


class Severity(b.s.msgspec.Struct, frozen=True):
    type: str
    score: str


class Reference(b.s.msgspec.Struct, frozen=True):
    type: str
    url: str


class ReportingAdvisory(b.s.msgspec.Struct, frozen=True):
    id: str
    aliases: tuple[str, ...] = ()
    summary: str | None = None
    published: str | None = None
    modified: str | None = None
    withdrawn: str | None = None
    severity: tuple[Severity, ...] = ()
    references: tuple[Reference, ...] = ()


def main():
    original_finish = b.finish
    original_advisory = b.Batch.advisory

    def projected(handle, protobuf=False):
        result = original_finish(handle, protobuf)
        result.identities = tuple(
            b.s.msgspec.msgpack.decode(result.raw(i), type=ReportingAdvisory)
            for i in range(len(result.identities))
        )
        result.chunks = ()
        return result

    b.finish = projected
    b.Batch.advisory = lambda self, i: self.identities[i]
    try:
        for count, overlap in [(1, 0.7), (10, 1.0), (10, 0.7)]:
            row = b.measure(count, overlap, "batch")
            print(
                json.dumps({
                    key: row[key]
                    for key in (
                        "images",
                        "overlap",
                        "retained_MiB",
                        "c_MiB",
                        "packages",
                        "advisories",
                    )
                }),
                flush=True,
            )
    finally:
        b.finish = original_finish
        b.Batch.advisory = original_advisory


if __name__ == "__main__":
    main()
