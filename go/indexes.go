package main

import (
	"context"
	"slices"
)

type reportIndex struct {
	Name    string   `json:"name"`
	Offsets []uint32 `json:"offsets"`
	Members []uint32 `json:"members"`
	Range   bool     `json:"range"`
}

func checkContext(ctx context.Context) {
	if ctx != nil && ctx.Err() != nil {
		panic(ctx.Err())
	}
}

// Build one relationship at a time with count/prefix-sum/fill. No per-key
// lists or sets; the temporary membership allocation is compacted in place.
func makeIndex(ctx context.Context, name string, size int, contiguous bool, edges func(func(int, int))) reportIndex {
	offsets := make([]uint32, size+1)
	edges(func(key, value int) { offsets[key+1] = checked(int(offsets[key+1]) + 1) })
	for i := 1; i < len(offsets); i++ {
		checkContext(ctx)
		offsets[i] = checked(int(offsets[i]) + int(offsets[i-1]))
	}
	if contiguous {
		return reportIndex{Name: name, Offsets: offsets, Members: []uint32{}, Range: true}
	}
	members := make([]uint32, offsets[size])
	cursor := slices.Clone(offsets[:size])
	edges(func(key, value int) { members[cursor[key]] = checked(value); cursor[key]++ })
	n := 0
	for i := range size {
		checkContext(ctx)
		group := members[offsets[i]:offsets[i+1]]
		slices.Sort(group)
		group = slices.Compact(group)
		offsets[i] = checked(n)
		n += copy(members[n:], group)
	}
	offsets[size] = checked(n)
	return reportIndex{Name: name, Offsets: offsets, Members: slices.Clone(members[:n])}
}

func (r *reportStore) buildIndexes(ctx context.Context) {
	occurrences, findings := len(r.Occurrences), len(r.Findings)
	definitions := []struct {
		name       string
		size       int
		contiguous bool
	}{
		{"image_occurrences", len(r.Images), true}, {"image_findings", len(r.Images), true},
		{"occurrence_findings", occurrences, true},
		{"image_packages", len(r.Images), false}, {"image_vulnerable_packages", len(r.Images), false},
		{"image_noncompliant_packages", len(r.Images), false}, {"image_vulnerabilities", len(r.Images), false},
		{"package_present_images", len(r.Packages), false}, {"package_vulnerable_images", len(r.Packages), false},
		{"package_noncompliant_images", len(r.Packages), false}, {"package_affected_images", len(r.Packages), false},
		{"vulnerability_affected_images", len(r.Vulnerabilities), false}, {"advisory_affected_images", len(r.AdvisorySources), false},
		{"vulnerability_findings", len(r.Vulnerabilities), false}, {"advisory_findings", len(r.AdvisorySources), false},
		{"package_findings", len(r.Packages), false},
	}
	for _, d := range definitions {
		visit := func(edge func(int, int)) {
			if d.name == "image_occurrences" || d.name == "image_packages" || d.name == "package_present_images" || d.name == "image_noncompliant_packages" || d.name == "package_noncompliant_images" || d.name == "package_affected_images" {
				for o := range occurrences {
					if o%1024 == 0 {
						checkContext(ctx)
					}
					im, p, lic := int(r.Occurrences[o].Image), int(r.Occurrences[o].Package), int(r.Occurrences[o].License)
					switch d.name {
					case "image_occurrences":
						edge(im, o)
					case "image_packages":
						edge(im, p)
					case "package_present_images":
						edge(p, im)
					default:
						if r.Licenses[lic].Status == "noncompliant" {
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
				o, a, v := int(r.Findings[f].Occurrence), int(r.Findings[f].Advisory), int(r.Findings[f].Vulnerability)
				im, p := int(r.Occurrences[o].Image), int(r.Occurrences[o].Package)
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
		r.Indexes = append(r.Indexes, makeIndex(ctx, d.name, d.size, d.contiguous, visit))
	}
}
