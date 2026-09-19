package main

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"
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
		names := []string{"Z", "CVE-2026-9", "B", "CVE-2026-1", "A", "zeta", "alpha", "0-singleton"}
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

func TestReportFieldValues(t *testing.T) {
	b := newBuilder()
	empty, timestamp, yes, no := "", "2026-01-01T00:00:00.123456789Z", true, false
	aliases := make([]string, 3)
	for i := range aliases {
		aliases[i] = fmt.Sprint("alias-", i)
	}
	advisory := reportAdvisory{
		ID: "A", Aliases: aliases, Summary: "summary", Modified: &timestamp, Published: &empty,
		Severities: []reportSeverity{{"CVSS_V3", "NVD", "vector"}},
		References: []reportReference{{"WEB", "https://example.test"}}, DatabaseSeverity: &empty,
	}
	packed := b.packAdvisory(advisory)
	b.advisory.intern(&b.report.AdvisorySources, packed)
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
	for i := range aliases {
		if got := r.value(5, 0, 0, 2, int64(i)); got.text != aliases[i] {
			t.Fatal("advisory alias value")
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
		v := r.value(10, uint32(i), 0, 2, -1)
		if policy == nil && v.tag != 0 || policy != nil && (v.tag != 5 || v.number != uint32(len(policy))) {
			t.Fatal("nil and empty policies conflated")
		}
	}
	for _, flag := range []*bool{nil, &no, &yes} {
		assessment := reportAssessment{Called: flag, Unimportant: flag, MaxSeverity: "HIGH"}
		i := b.assessment.intern(&r.Assessments, b.packAssessment(assessment))
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
	if r.value(1, 0, 0, 5, -1).number != 4 {
		t.Fatal("each image must retain its findings")
	}
	for i, want := range []uint32{1, 0, 1, 0} {
		if got := r.value(7, uint32(i), 0, 5, -1); got.kind != 4 || got.row != want {
			t.Fatalf("finding %d: %+v, want vulnerability %d", i, got, want)
		}
	}
}

func TestReportRelationships(t *testing.T) {
	b := newBuilder()
	a := &reportAdvisory{ID: "A"}
	for range 2 {
		p := pendingImage{image: reportImage{Status: "complete"}}
		p.union([]string{"A", "CVE-2026-1"})
		for occurrence := range 3 {
			name, status := "vulnerable", "compliant"
			if occurrence == 2 {
				name, status = "licensed", "noncompliant"
			}
			p.occurrence(reportPackage{Name: name}, reportContext{}, reportLicense{Status: status})
			if occurrence < 2 {
				p.finding(a, reportFix{Status: "unknown"}, reportAssessment{})
			}
		}
		b.merge(p)
	}
	r := b.finish()
	for _, tc := range []struct {
		kind, row, field, target uint32
		want                     []uint32
	}{
		{2, 0, 6, 6, []uint32{0, 1, 2}}, {2, 1, 6, 6, []uint32{3, 4, 5}},
		{2, 0, 7, 7, []uint32{0, 1}}, {2, 1, 7, 7, []uint32{2, 3}},
		{2, 0, 8, 3, []uint32{0, 1}}, {2, 0, 9, 3, []uint32{0}},
		{2, 0, 10, 3, []uint32{1}}, {2, 0, 11, 4, []uint32{0}},
		{3, 0, 7, 2, []uint32{0, 1}}, {3, 1, 7, 2, []uint32{0, 1}},
		{3, 0, 8, 2, []uint32{0, 1}}, {3, 1, 8, 2, nil},
		{3, 0, 9, 2, nil}, {3, 1, 9, 2, []uint32{0, 1}},
		{3, 0, 10, 2, []uint32{0, 1}}, {3, 1, 10, 2, []uint32{0, 1}},
		{3, 0, 11, 7, []uint32{0, 1, 2, 3}}, {3, 1, 11, 7, nil},
		{4, 0, 3, 2, []uint32{0, 1}}, {4, 0, 4, 7, []uint32{0, 1, 2, 3}},
		{5, 0, 10, 2, []uint32{0, 1}}, {5, 0, 11, 7, []uint32{0, 1, 2, 3}},
		{6, 0, 5, 7, []uint32{0}}, {6, 1, 5, 7, []uint32{1}},
		{6, 2, 5, 7, nil},
	} {
		length := r.value(tc.kind, tc.row, 0, tc.field, -1)
		if length.number != uint32(len(tc.want)) {
			t.Fatalf("relationship %+v length: %v", tc, length.number)
		}
		for i, row := range tc.want {
			got := r.value(tc.kind, tc.row, 0, tc.field, int64(i))
			if got.kind != tc.target || got.row != row {
				t.Fatalf("relationship %+v member %d: %+v", tc, i, got)
			}
		}
	}
}
