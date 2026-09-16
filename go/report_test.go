package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
)

func TestPackageFixesPreserveMembershipAndVersionRules(t *testing.T) {
	for _, tc := range []struct {
		name, ecosystem, affectedEcosystem, version, rangeType string
		want                                                   []string
	}{
		{"filtered", "PyPI", "PyPI", "1.0", "ECOSYSTEM", []string{"2.0", "3.0"}},
		{"unknown-version", "PyPI", "PyPI", "not-a-version", "ECOSYSTEM", []string{"0.5", "1.0", "2.0", "3.0"}},
		{"ubuntu", "Ubuntu:24.04", "Ubuntu:24.04:Pro:LTS", "1.0", "ECOSYSTEM", []string{"2.0", "3.0"}},
		{"other-ecosystem", "PyPI", "npm", "1.0", "ECOSYSTEM", []string{}},
		{"git", "PyPI", "PyPI", "1.0", "GIT", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := fmt.Sprintf(`{
				"package":{"name":"example","ecosystem":%q,"version":%q},
				"groups":[{"ids":["A","A"]},{"ids":["A","B"]},{"ids":["missing"]}],
				"vulnerabilities":[
					{"id":"A","affected":[{"package":{"name":"example","ecosystem":%q},
					"ranges":[{"type":%q,"events":[{"fixed":"2.0"},{"fixed":"0.5"},{"fixed":"1.0"},{"fixed":"2.0"}]}]}]},
					{"id":"A","affected":[{"package":{"name":"example","ecosystem":%q},
					"ranges":[{"type":%q,"events":[{"fixed":"3.0"}]}]}]},
					{"id":"B","affected":[{"package":{"name":"other","ecosystem":%q},
					"ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"99"}]}]}]},
					{"id":"unmatched","affected":[{"package":{"name":"example","ecosystem":%q},
					"ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"99"}]}]}]}
				]}`, tc.ecosystem, tc.version, tc.affectedEcosystem, tc.rangeType, tc.affectedEcosystem, tc.rangeType, tc.affectedEcosystem, tc.affectedEcosystem)
			var pkg models.PackageVulns
			if err := json.Unmarshal([]byte(data), &pkg); err != nil {
				t.Fatal(err)
			}
			for _, groupCount := range []int{3, 1, 0} {
				pkg.Groups = pkg.Groups[:groupCount]
				fixes := make([][]string, groupCount)
				packageFixes(pkg, fixes)
				for i, got := range fixes {
					want := tc.want
					if i == 2 {
						want = []string{}
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("%d groups, group %d: got %v, want %v", groupCount, i, got, want)
					}
				}
			}
		})
	}
}

func TestCompactDuplicatePackagesPreserveOutput(t *testing.T) {
	req := request{AllowedLicenses: []string{"MIT"}}
	one := compactResults(reportFixture(t, 1, 3, true), req, scanMetadata{})
	many := compactResults(reportFixture(t, 100, 3, true), req, scanMetadata{})
	if !reflect.DeepEqual(one, many) {
		t.Fatal("duplicate package occurrences changed the report")
	}
	for _, v := range many.Vulnerabilities {
		if cap(v.Packages) != len(v.Packages) {
			t.Fatal("duplicate package edges retained excess storage")
		}
	}
}

func TestUniqueReleasesLargeDuplicateStorage(t *testing.T) {
	values := make([]string, 1000)
	for i := range values {
		values[i] = "same"
	}
	got := unique(values)
	if !slices.Equal(got, []string{"same"}) || cap(got) != 1 {
		t.Fatalf("got %v with capacity %d", got, cap(got))
	}
}

func TestEmptyCompactCollectionsStayArrays(t *testing.T) {
	r := compactResults(models.VulnerabilityResults{}, request{AllowedLicenses: []string{}}, scanMetadata{})
	if r.Packages == nil || r.Vulnerabilities == nil || r.Licenses.Violations == nil || r.Licenses.AllowedLicenses == nil {
		t.Fatal("empty collections must serialize as arrays")
	}
}

// Build outside benchmark timing; each group has its own advisory and fix.
func reportFixture(t testing.TB, packages, groups int, duplicate bool) models.VulnerabilityResults {
	t.Helper()
	rows := make([]any, 0, packages)
	for p := range packages {
		version := fmt.Sprintf("1.0.%d", p)
		if duplicate {
			version = "1.0.0"
		}
		advisories, findings := []any{}, []any{}
		for g := range groups {
			id := fmt.Sprintf("TEST-%04d", g)
			findings = append(findings, map[string]any{"ids": []string{id}, "aliases": []string{id}, "max_severity": "7.5"})
			advisories = append(advisories, map[string]any{
				"id": id,
				"affected": []any{map[string]any{
					"package": map[string]any{"name": "example", "ecosystem": "PyPI"},
					"ranges":  []any{map[string]any{"type": "ECOSYSTEM", "events": []any{map[string]string{"fixed": "2.0.0"}}}},
				}},
			})
		}
		rows = append(rows, map[string]any{
			"package": map[string]string{"name": "example", "version": version, "ecosystem": "PyPI"},
			"groups":  findings, "vulnerabilities": advisories,
			"licenses": []string{"MIT", "GPL-3.0"}, "license_violations": []string{"GPL-3.0"},
		})
	}
	data, err := json.Marshal(map[string]any{"results": []any{map[string]any{"packages": rows}}})
	if err != nil {
		t.Fatal(err)
	}
	var result models.VulnerabilityResults
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func BenchmarkCompactResults(b *testing.B) {
	for _, tc := range []struct {
		name             string
		packages, groups int
		duplicate        bool
	}{
		{"small", 1, 1, false},
		{"unique", 1000, 1, false},
		{"duplicate", 1000, 1, true},
		{"many_groups", 10, 200, false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			input := reportFixture(b, tc.packages, tc.groups, tc.duplicate)
			req := request{AllowedLicenses: []string{"MIT"}}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				compactResults(input, req, scanMetadata{})
			}
		})
	}
}
