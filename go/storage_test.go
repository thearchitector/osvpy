package main

import (
	"context"
	"fmt"
	"math/rand/v2"
	"reflect"
	"runtime"
	"slices"
	"testing"
	"unsafe"
)

func TestAliasFinalizationOrdering(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		b := newBuilder()
		groups := [][]string{
			{"Z", "CVE-2026-9", "B", "B"},
			{"CVE-2026-1", "A"}, {"B", "A"},
			{"zeta", "alpha"}, {"0-singleton"},
		}
		if reverse {
			slices.Reverse(groups)
		}
		for _, group := range groups {
			b.union(group)
		}
		// Include every alias as an advisory, including noncanonical CVEs.
		names := slices.Clone(b.names)
		for _, name := range names {
			b.advisory.intern(&b.report.AdvisorySources, b.packAdvisory(reportAdvisory{ID: name}))
		}
		r := b.finish()
		want := []reportVulnerability{
			{ID: "0-singleton", Aliases: []string{}},
			{ID: "CVE-2026-1", Aliases: []string{"A", "B", "CVE-2026-9", "Z"}},
			{ID: "alpha", Aliases: []string{"zeta"}},
		}
		if r.Vulnerabilities.Len() != len(want) {
			t.Fatalf("vulnerability count: %d", r.Vulnerabilities.Len())
		}
		for i, v := range want {
			if got := r.vulnerabilityAt(i); !reflect.DeepEqual(got, v) {
				t.Fatalf("vulnerability %d: %+v, want %+v", i, got, v)
			}
		}
		for i, name := range names {
			v := r.vulnerabilityAt(int(*r.AdvisoryVulnerabilities.At(i)))
			if name != v.ID && !slices.Contains(v.Aliases, name) {
				t.Fatalf("advisory %q mapped to %+v", name, v)
			}
		}
		if !reflect.DeepEqual(*b, batchBuilder{}) {
			t.Fatal("builder retains scratch state")
		}
	}
}

func TestLargeAliasFinalization(t *testing.T) {
	b := newBuilder()
	const count = 6*slabSize + 17
	want := make([][]string, 3)
	for i := count - 1; i >= 0; i-- {
		name, group := fmt.Sprintf("alias-%06d", i), i%3
		root := fmt.Sprintf("CVE-2026-%d", group)
		b.union([]string{name, root, name})
		b.advisory.intern(&b.report.AdvisorySources, b.packAdvisory(reportAdvisory{ID: name}))
		want[group] = append(want[group], name)
	}
	r := b.finish()
	if r.Vulnerabilities.Len() != 3 || r.AdvisoryVulnerabilities.Len() != count {
		t.Fatal("lost aliases or advisory mappings")
	}
	for group := range want {
		slices.Sort(want[group])
		v := r.vulnerabilityAt(group)
		if v.ID != fmt.Sprintf("CVE-2026-%d", group) || !slices.Equal(v.Aliases, want[group]) {
			t.Fatalf("group %d changed across slabs", group)
		}
	}
	for i := range count {
		if got := *r.AdvisoryVulnerabilities.At(i); got != uint32((count-1-i)%3) {
			t.Fatalf("advisory %d mapped to %d", i, got)
		}
	}
}

func TestAliasCancellation(t *testing.T) {
	for _, finish := range []bool{false, true} {
		t.Run(fmt.Sprint(finish), func(t *testing.T) {
			b := newBuilder()
			b.union([]string{"A", "B"})
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			b.ctx = ctx
			defer func() {
				if got := recover(); got != context.Canceled {
					t.Fatalf("got %v, want cancellation", got)
				}
			}()
			if finish {
				b.finish()
			} else {
				b.union([]string{"C", "D"})
			}
		})
	}
}

// Setup is excluded from timing and allocation counts. For process peak RSS,
// run a compiled test binary under /usr/bin/time -v with -test.benchtime=1x;
// that peak includes ingestion, finalization, and allocator-retained pages.
func BenchmarkFinishLargeAliasUniverse(b *testing.B) {
	for _, groups := range []int{32, 20000} {
		b.Run(fmt.Sprintf("groups=%d", groups), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				builder := newBuilder()
				for alias := range 120000 {
					name := fmt.Sprintf("alias-%06d", alias)
					builder.union([]string{name, fmt.Sprintf("CVE-2026-%06d", alias%groups)})
					builder.advisory.intern(&builder.report.AdvisorySources, builder.packAdvisory(reportAdvisory{ID: name}))
				}
				b.StartTimer()
				report := builder.finish()
				b.StopTimer()
				runtime.KeepAlive(report)
			}
		})
	}
}

func TestSlabsStableRowsAndReclaimableSlack(t *testing.T) {
	var rows slabs[uint32]
	rows.Append(17)
	first := rows.At(0)
	for i := 1; i < 4*slabSize+17; i++ {
		rows.Append(uint32(i))
	}
	if rows.At(0) != first || *first != 17 {
		t.Fatal("growth moved a row")
	}
	for _, chunk := range rows.chunks {
		if len(chunk) != slabSize || cap(chunk) != slabSize {
			t.Fatal("unbounded row slab")
		}
	}
	directory := rows.chunks
	rows.Truncate(slabSize + 7)
	if len(rows.chunks) != 2 || rows.At(0) != first {
		t.Fatal("compaction moved or retained extra slabs")
	}
	for _, chunk := range directory[2:] {
		if chunk != nil {
			t.Fatal("unused slab remains reachable through directory")
		}
	}
	for _, value := range rows.chunks[1][7:] {
		if value != 0 {
			t.Fatal("unused tail was not cleared")
		}
	}
	rows.Append(99)
	if *rows.At(slabSize + 7) != 99 {
		t.Fatal("append after truncate")
	}
	rows.Truncate(0)
	if len(rows.chunks) != 0 || rows.Len() != 0 {
		t.Fatal("empty table retained slabs")
	}
}

func TestSegmentedIndexMatchesSortedSets(t *testing.T) {
	const keys = 11
	random := rand.New(rand.NewPCG(31, 47))
	type edge struct{ key, value int }
	var edges []edge
	want := make([][]uint32, keys)
	for range 20000 {
		key, value := random.IntN(keys-1), random.IntN(2*slabSize+3)
		edges = append(edges, edge{key, value})
		want[key] = append(want[key], uint32(value))
	}
	visit := func(yield func(int, int)) {
		for _, e := range edges {
			yield(e.key, e.value)
		}
	}
	index := makeIndex(nil, "test", keys, false, visit)
	for key := range keys {
		slices.Sort(want[key])
		want[key] = slices.Compact(want[key])
		start, end := int(*index.Offsets.At(key)), int(*index.Offsets.At(key + 1))
		if end-start != len(want[key]) {
			t.Fatalf("key %d length: %d != %d", key, end-start, len(want[key]))
		}
		for i, value := range want[key] {
			if *index.Members.At(start + i) != value {
				t.Fatalf("key %d member %d", key, i)
			}
		}
	}
	if len(index.Members.chunks) != (index.Members.Len()+slabSize-1)/slabSize {
		t.Fatal("retained unused membership slabs")
	}
	// Heavy duplicate compaction must release nearly the entire allocation.
	index = makeIndex(nil, "duplicates", 1, false, func(yield func(int, int)) {
		for range 20 * slabSize {
			yield(0, 7)
		}
	})
	if index.Members.Len() != 1 || len(index.Members.chunks) != 1 || *index.Members.At(0) != 7 {
		t.Fatal("duplicate membership slack was retained")
	}
}

func TestIndexCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	defer func() {
		if got := recover(); got != context.Canceled {
			t.Fatalf("got %v, want cancellation", got)
		}
	}()
	makeIndex(ctx, "cancelled", 2, false, func(yield func(int, int)) { yield(1, 1) })
}

func TestListFingerprintCollisions(t *testing.T) {
	b := newBuilder()
	a := b.internWords([]uint32{1, 2}, 7)
	c := b.internWords([]uint32{1, 3}, 7)
	d := b.internWords([]uint32{1, 2, 3}, 7)
	if a == c || a == d || c == d {
		t.Fatal("fingerprint collision merged unequal values")
	}
	for _, tc := range []struct {
		words []uint32
		want  span
	}{{[]uint32{1, 2}, a}, {[]uint32{1, 3}, c}, {[]uint32{1, 2, 3}, d}} {
		if got := b.internWords(tc.words, 7); got != tc.want {
			t.Fatal("collision chain lost existing entry")
		}
	}
	if b.report.Words.Len() != 7 {
		t.Fatal("deduplication appended payload")
	}
}

func TestCompactPayloadAndNativeReads(t *testing.T) {
	b := newBuilder()
	empty, timestamp, yes, no := "", "2026-01-01T00:00:00.123456789Z", true, false
	aliases := make([]string, slabSize+7)
	for i := range aliases {
		aliases[i] = fmt.Sprint("alias-", i)
	}
	advisory := reportAdvisory{
		ID: "A", Aliases: aliases, Summary: "summary", Modified: &timestamp, Published: &empty,
		Severities: []reportSeverity{{"CVSS_V3", "NVD", "vector"}},
		References: []reportReference{{"WEB", "https://example.test"}}, DatabaseSeverity: &empty,
	}
	packed := b.packAdvisory(advisory)
	id := b.advisory.intern(&b.report.AdvisorySources, packed)
	words, strings := b.report.Words.Len(), b.report.Strings.Len()
	if b.advisory.intern(&b.report.AdvisorySources, b.packAdvisory(advisory)) != id ||
		b.report.Words.Len() != words || b.report.Strings.Len() != strings {
		t.Fatal("retained repeated payload")
	}
	if got := b.report.advisoryAt(id); !reflect.DeepEqual(got, advisory) {
		t.Fatalf("payload round trip: %+v", got)
	}
	r := &b.report
	if got := r.value(5, 0, 0, 4, -1); got.text != timestamp || got.tag != 1 {
		t.Fatal("timestamp")
	}
	if got := r.value(5, 0, 0, 5, -1); got.tag != 1 || got.text != "" {
		t.Fatal("present empty string")
	}
	if got := r.value(5, 0, 0, 6, -1); got.tag != 0 {
		t.Fatal("absent string")
	}
	for _, i := range []int{0, slabSize - 1, slabSize, slabSize + 6} {
		if got := r.value(5, 0, 0, 2, int64(i)); got.text != aliases[i] {
			t.Fatal("span crossing slab boundary")
		}
	}
	for _, tc := range []struct {
		kind, field uint32
		want        string
	}{{14, 1, "CVSS_V3"}, {14, 2, "NVD"}, {14, 3, "vector"}, {15, 1, "WEB"}, {15, 2, "https://example.test"}} {
		if got := r.value(tc.kind, 0, 0, tc.field, -1); got.text != tc.want {
			t.Fatalf("nested value %+v", tc)
		}
	}
	for _, policy := range [][]string{nil, {}, {"MIT"}} {
		lic := reportLicense{Status: "compliant", Policy: policy}
		i := b.license.intern(&r.Licenses, b.packLicense(lic))
		if !reflect.DeepEqual(r.licenseAt(i), lic) {
			t.Fatal("license round trip")
		}
		v := r.value(10, uint32(i), 0, 2, -1)
		if policy == nil && v.tag != 0 || policy != nil && (v.tag != 5 || v.number != float64(len(policy))) {
			t.Fatal("nil and empty policies conflated")
		}
	}
	for _, flag := range []*bool{nil, &no, &yes} {
		assessment := reportAssessment{Called: flag, Unimportant: flag, MaxSeverity: "HIGH"}
		i := b.assessment.intern(&r.Assessments, b.packAssessment(assessment))
		if !reflect.DeepEqual(r.assessmentAt(i), assessment) {
			t.Fatal("assessment round trip")
		}
		v := r.value(9, uint32(i), 0, 1, -1)
		if flag == nil && v.tag != 0 || flag != nil && (v.tag != 2 || (v.number == 1) != *flag) {
			t.Fatal("optional boolean")
		}
	}
	// Input slice mutation cannot change retained payloads.
	aliases[0] = "mutated"
	if r.value(5, 0, 0, 2, 0).text != "alias-0" {
		t.Fatal("retained source slice")
	}
}

func TestRetainedRowLayout(t *testing.T) {
	if unsafe.Sizeof(findingRow{}) != 16 {
		t.Fatal("finding row must contain four IDs")
	}
	var pointerFree func(reflect.Type) bool
	pointerFree = func(typ reflect.Type) bool {
		if typ.Kind() == reflect.Struct {
			for field := range typ.Fields() {
				if !pointerFree(field.Type) {
					return false
				}
			}
			return true
		}
		return typ.Kind() == reflect.Uint32 || typ.Kind() == reflect.Uint8
	}
	for _, value := range []any{storedPackage{}, storedAdvisory{}, storedVulnerability{}, storedContext{}, storedAssessment{}, storedLicense{}, storedFix{}, findingRow{}, occurrenceRow{}} {
		if !pointerFree(reflect.TypeOf(value)) {
			t.Fatalf("pointer-bearing retained row: %T", value)
		}
	}
}

func TestAdvisoryVulnerabilityMapping(t *testing.T) {
	b := newBuilder()
	a, c := reportAdvisory{ID: "A"}, reportAdvisory{ID: "B"}
	b.union([]string{"A", "CVE-2026-9"})
	b.union([]string{"B", "CVE-2026-1"})
	for range 2 {
		b.imageAdvisories = make(map[*reportAdvisory]int)
		b.occurrence(reportPackage{}, reportContext{}, reportLicense{Status: "not_evaluated"})
		for _, advisory := range []*reportAdvisory{&a, &c} {
			b.finding(advisory, reportFix{Status: "unknown"}, reportAssessment{})
		}
		b.report.Images.Append(reportImage{})
	}
	r := b.finish()
	if r.AdvisoryVulnerabilities.Len() != 2 || r.Findings.Len() != 4 {
		t.Fatal("mapping must have one entry per advisory")
	}
	for i, want := range []uint32{1, 0, 1, 0} {
		if got := r.value(7, uint32(i), 0, 5, -1); got.kind != 4 || got.row != want {
			t.Fatalf("finding %d: %+v, want vulnerability %d", i, got, want)
		}
	}
}

func TestMaterializedRelationshipsAcrossSlabs(t *testing.T) {
	b := newBuilder()
	a := reportAdvisory{ID: "A"}
	const occurrencesPerImage = slabSize + 3
	for image := range 2 {
		b.imageAdvisories = make(map[*reportAdvisory]int)
		for i := range occurrencesPerImage {
			pkg := reportPackage{Name: fmt.Sprint(i % 2)}
			lic := reportLicense{Status: "compliant"}
			if i%2 == 1 {
				lic.Status = "noncompliant"
			}
			b.occurrence(pkg, reportContext{}, lic)
			b.union([]string{"A", "CVE-2026-1"})
			for range 2 {
				b.finding(&a, reportFix{Status: "unknown"}, reportAssessment{})
			}
		}
		b.report.Images.Append(reportImage{Requested: fmt.Sprint(image)})
	}
	first := b.report.Findings.At(0)
	r := b.finish()
	if !reflect.DeepEqual(*b, batchBuilder{}) {
		t.Fatal("builder retains ingestion state")
	}
	if r.Findings.At(0) != first {
		t.Fatal("finalization copied rows")
	}
	if len(r.Indexes) != 16 || r.AdvisoryVulnerabilities.Len() != 1 {
		t.Fatal("missing materialized index or advisory mapping")
	}
	for i := range r.Findings.Len() {
		if got := r.value(7, uint32(i), 0, 5, -1); got.kind != 4 || got.row != 0 {
			t.Fatal("finding vulnerability mapping")
		}
	}
	for _, idx := range r.Indexes {
		for key := 0; key+1 < idx.Offsets.Len(); key++ {
			var want []uint32
			switch idx.Name {
			case "image_occurrences":
				for i := range occurrencesPerImage {
					want = append(want, uint32(key*occurrencesPerImage+i))
				}
			case "image_findings":
				for i := range 2 * occurrencesPerImage {
					want = append(want, uint32(key*2*occurrencesPerImage+i))
				}
			case "occurrence_findings":
				want = []uint32{uint32(2 * key), uint32(2*key + 1)}
			case "image_packages", "image_vulnerable_packages":
				want = []uint32{0, 1}
			case "image_noncompliant_packages":
				want = []uint32{1}
			case "image_vulnerabilities":
				want = []uint32{0}
			case "package_present_images", "package_vulnerable_images", "package_affected_images", "vulnerability_affected_images", "advisory_affected_images":
				want = []uint32{0, 1}
			case "package_noncompliant_images":
				if key == 1 {
					want = []uint32{0, 1}
				}
			case "vulnerability_findings", "advisory_findings":
				for i := range 4 * occurrencesPerImage {
					want = append(want, uint32(i))
				}
			case "package_findings":
				for i := range 4 * occurrencesPerImage {
					if (i/2%occurrencesPerImage)%2 == key {
						want = append(want, uint32(i))
					}
				}
			default:
				t.Fatalf("unexpected index %s", idx.Name)
			}
			start, end := *idx.Offsets.At(key), *idx.Offsets.At(key + 1)
			if int(end-start) != len(want) {
				t.Fatalf("%s key %d length %d != %d", idx.Name, key, end-start, len(want))
			}
			for i, value := range want {
				got := start + uint32(i)
				if !idx.Range {
					got = *idx.Members.At(int(got))
				}
				if got != value {
					t.Fatalf("%s key %d member %d: %d != %d", idx.Name, key, i, got, value)
				}
			}
			if idx.Range && idx.Members.Len() != 0 {
				t.Fatal("contiguous relation retained memberships")
			}
		}
	}
}
