package main

import (
	"context"
	"unsafe"
)

// Inject into an isolated workspace; observations impose no expected values.
type indexObservation struct {
	Name                                             string
	Slot                                             int
	Raw, UniqueBound, TemporaryBytes                 uint64
	OffsetRows, MemberRows, OffsetSlabs, MemberSlabs int
}

func observeIndexPlan(ctx context.Context, r *reportStore) []indexObservation {
	var observations []indexObservation
	for _, plan := range r.indexBuildOrder(ctx) {
		observations = append(observations, indexObservation{
			Name: plan.name, Slot: plan.slot, Raw: plan.raw,
			UniqueBound: plan.retained, TemporaryBytes: plan.temporary,
		})
	}
	return observations
}

func observeIndexes(r *reportStore) []indexObservation {
	var observations []indexObservation
	for slot, index := range r.Indexes {
		observations = append(observations, indexObservation{
			Name: index.Name, Slot: slot,
			OffsetRows: index.Offsets.Len(), MemberRows: index.Members.Len(),
			OffsetSlabs: len(index.Offsets.chunks), MemberSlabs: len(index.Members.chunks),
		})
	}
	return observations
}

func observeRowSizes() map[string]uintptr {
	return map[string]uintptr{
		"package": unsafe.Sizeof(storedPackage{}), "advisory": unsafe.Sizeof(storedAdvisory{}),
		"vulnerability": unsafe.Sizeof(storedVulnerability{}), "context": unsafe.Sizeof(storedContext{}),
		"assessment": unsafe.Sizeof(storedAssessment{}), "license": unsafe.Sizeof(storedLicense{}),
		"fix": unsafe.Sizeof(storedFix{}), "finding": unsafe.Sizeof(findingRow{}),
		"occurrence": unsafe.Sizeof(occurrenceRow{}),
	}
}
