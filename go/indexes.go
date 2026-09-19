package main

import (
	"cmp"
	"context"
	"math"
	"slices"
	"sort"
)

type reportIndex struct {
	Name    string
	Offsets slabs[uint32]
	Members slabs[uint32]
	Range   bool
}

type memberWindow struct {
	members    *slabs[uint32]
	start, end int
	ctx        context.Context
}

func (w memberWindow) Len() int { return w.end - w.start }
func (w memberWindow) Less(i, j int) bool {
	return *w.members.At(w.start + i) < *w.members.At(w.start + j)
}
func (w memberWindow) Swap(i, j int) {
	checkContext(w.ctx)
	a, b := w.members.At(w.start+i), w.members.At(w.start+j)
	*a, *b = *b, *a
}

func checkContext(ctx context.Context) {
	if ctx != nil && ctx.Err() != nil {
		panic(ctx.Err())
	}
}

func addIndexCount(a, b uint32) uint32 {
	if b > math.MaxUint32-a {
		panic("report_overflow")
	}
	return a + b
}

func prefixIndexCounts(ctx context.Context, offsets *slabs[uint32]) {
	for i := 1; i < offsets.Len(); i++ {
		checkContext(ctx)
		*offsets.At(i) = addIndexCount(*offsets.At(i), *offsets.At(i - 1))
	}
}

// Count/prefix-sum/fill and sort/compact operate directly on segmented storage.
// Compaction releases unused slabs without flattening the membership array.
func makeIndex(ctx context.Context, name string, size int, contiguous bool, edges func(func(int, int))) reportIndex {
	var offsets slabs[uint32]
	offsets.Resize(size + 1)
	var total uint32
	edges(func(key, value int) {
		if total%1024 == 0 {
			checkContext(ctx)
		}
		total = addIndexCount(total, 1)
		p := offsets.At(key + 1)
		*p = addIndexCount(*p, 1)
	})
	prefixIndexCounts(ctx, &offsets)
	if contiguous {
		return reportIndex{Name: name, Offsets: offsets, Range: true}
	}
	var members, cursor slabs[uint32]
	members.Resize(int(*offsets.At(size)))
	for i := range size {
		cursor.Append(*offsets.At(i))
	}
	edges(func(key, value int) { p := cursor.At(key); *members.At(int(*p)) = checked(value); *p++ })
	n := 0
	window := memberWindow{members: &members, ctx: ctx}
	for i := range size {
		checkContext(ctx)
		start, end := int(*offsets.At(i)), int(*offsets.At(i + 1))
		window.start, window.end = start, end
		sort.Sort(&window)
		*offsets.At(i) = checked(n)
		var previous uint32
		for j := start; j < end; j++ {
			if j%1024 == 0 {
				checkContext(ctx)
			}
			value := *members.At(j)
			if j == start || value != previous {
				*members.At(n) = value
				n++
				previous = value
			}
		}
	}
	*offsets.At(size) = checked(n)
	members.Truncate(n)
	return reportIndex{Name: name, Offsets: offsets, Members: members}
}

type indexDefinition struct {
	name       string
	size       int
	contiguous bool
}

type indexBuild struct {
	indexDefinition
	slot      int // ABI position, independent of construction order.
	raw       uint64
	retained  uint64 // Upper bound on unique memberships.
	temporary uint64 // Estimated construction bytes minus retained bytes.
}

func indexMemberBytes(n uint64) uint64 {
	return ((n + slabSize - 1) / slabSize) * slabSize * 4
}

func (r *reportStore) indexBuildOrder(ctx context.Context) []indexBuild {
	occurrences, findings := r.Occurrences.Len(), r.Findings.Len()
	definitions := []indexDefinition{
		{"image_occurrences", r.Images.Len(), true}, {"image_findings", r.Images.Len(), true},
		{"occurrence_findings", occurrences, true},
		{"image_packages", r.Images.Len(), false}, {"image_vulnerable_packages", r.Images.Len(), false},
		{"image_noncompliant_packages", r.Images.Len(), false}, {"image_vulnerabilities", r.Images.Len(), false},
		{"package_present_images", r.Packages.Len(), false}, {"package_vulnerable_images", r.Packages.Len(), false},
		{"package_noncompliant_images", r.Packages.Len(), false}, {"package_affected_images", r.Packages.Len(), false},
		{"vulnerability_affected_images", r.Vulnerabilities.Len(), false}, {"advisory_affected_images", r.AdvisorySources.Len(), false},
		{"vulnerability_findings", r.Vulnerabilities.Len(), false}, {"advisory_findings", r.AdvisorySources.Len(), false},
		{"package_findings", r.Packages.Len(), false},
	}
	var noncompliant uint64
	for o := range occurrences {
		if o%1024 == 0 {
			checkContext(ctx)
		}
		if r.Licenses.At(int(r.Occurrences.At(o).License)).Status == statusID("noncompliant") {
			noncompliant++
		}
	}
	order := make([]indexBuild, len(definitions))
	for slot, d := range definitions {
		checkContext(ctx)
		raw := uint64(findings)
		bound := raw
		switch d.name {
		case "image_occurrences", "image_packages", "package_present_images":
			raw = uint64(occurrences)
			bound = uint64(r.Images.Len()) * uint64(r.Packages.Len())
		case "image_noncompliant_packages", "package_noncompliant_images":
			raw = noncompliant
			bound = uint64(r.Images.Len()) * uint64(r.Packages.Len())
		case "image_vulnerable_packages", "package_vulnerable_images", "package_affected_images":
			if d.name == "package_affected_images" {
				raw += noncompliant
			}
			bound = uint64(r.Images.Len()) * uint64(r.Packages.Len())
		case "image_vulnerabilities", "vulnerability_affected_images":
			bound = uint64(r.Images.Len()) * uint64(r.Vulnerabilities.Len())
		case "advisory_affected_images":
			bound = uint64(r.Images.Len()) * uint64(r.AdvisorySources.Len())
		}
		if raw > math.MaxUint32 {
			panic("report_overflow")
		}
		retained, temporary := min(raw, bound), uint64(0)
		if d.contiguous {
			retained = 0
		} else {
			temporary = indexMemberBytes(raw) - indexMemberBytes(retained) + indexMemberBytes(uint64(d.size))
		}
		order[slot] = indexBuild{d, slot, raw, retained, temporary}
	}
	// For known final sizes, descending (construction - retained) minimizes
	// the peak across sequential builds. Pair-count bounds cheaply recognize
	// heavy overlap without retaining another set of relationship memberships.
	// Sparse graphs may deduplicate more than this conservative estimate.
	slices.SortFunc(order, func(a, b indexBuild) int {
		return cmp.Or(cmp.Compare(b.temporary, a.temporary), cmp.Compare(b.raw, a.raw), cmp.Compare(a.slot, b.slot))
	})
	return order
}

func (r *reportStore) buildIndexes(ctx context.Context) {
	occurrences, findings := r.Occurrences.Len(), r.Findings.Len()
	order := r.indexBuildOrder(ctx)
	r.Indexes = make([]reportIndex, len(order))
	for _, d := range order {
		visit := func(edge func(int, int)) {
			if d.name == "image_occurrences" || d.name == "image_packages" || d.name == "package_present_images" || d.name == "image_noncompliant_packages" || d.name == "package_noncompliant_images" || d.name == "package_affected_images" {
				for o := range occurrences {
					if o%1024 == 0 {
						checkContext(ctx)
					}
					im, p, lic := int(r.Occurrences.At(o).Image), int(r.Occurrences.At(o).Package), int(r.Occurrences.At(o).License)
					switch d.name {
					case "image_occurrences":
						edge(im, o)
					case "image_packages":
						edge(im, p)
					case "package_present_images":
						edge(p, im)
					default:
						if r.Licenses.At(lic).Status == statusID("noncompliant") {
							if d.name == "image_noncompliant_packages" {
								edge(im, p)
							} else {
								edge(p, im)
							}
						}
					}
				}
			}
			switch d.name {
			case "image_occurrences", "image_packages", "package_present_images", "image_noncompliant_packages", "package_noncompliant_images":
				return
			}
			for f := range findings {
				if f%1024 == 0 {
					checkContext(ctx)
				}
				o, a, v := int(r.Findings.At(f).Occurrence), int(r.Findings.At(f).Advisory), int(*r.AdvisoryVulnerabilities.At(int(r.Findings.At(f).Advisory)))
				im, p := int(r.Occurrences.At(o).Image), int(r.Occurrences.At(o).Package)
				switch d.name {
				case "image_findings":
					edge(im, f)
				case "occurrence_findings":
					edge(o, f)
				case "image_vulnerabilities":
					edge(im, v)
				case "image_vulnerable_packages":
					edge(im, p)
				case "package_vulnerable_images", "package_affected_images":
					edge(p, im)
				case "vulnerability_affected_images":
					edge(v, im)
				case "advisory_affected_images":
					edge(a, im)
				case "vulnerability_findings":
					edge(v, f)
				case "advisory_findings":
					edge(a, f)
				case "package_findings":
					edge(p, f)
				}
			}
		}
		r.Indexes[d.slot] = makeIndex(ctx, d.name, d.size, d.contiguous, visit)
	}
}
