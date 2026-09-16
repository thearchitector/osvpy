package main

import (
	"encoding/json"
	"github.com/google/osv-scanner/v2/pkg/models"
	"reflect"
	"strings"
	"testing"
)

func fixture(t testing.TB, raw string) models.VulnerabilityResults {
	t.Helper()
	var p models.PackageVulns
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	return models.VulnerabilityResults{Results: []models.PackageSource{{Packages: []models.PackageVulns{p}}}}
}

const fixturePackage = `{"package":{"name":"example","version":"1.0","ecosystem":"PyPI"},"groups":[{"ids":["A"],"aliases":["CVE-2026-1","A"]}],"vulnerabilities":[{"id":"A","modified":"2026-01-01T00:00:00.123456789Z","affected":[{"package":{"name":"example","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"0.5"},{"fixed":"1.0"},{"fixed":"2.0"},{"fixed":"3.0"}]}]}]}]}`

func TestFixEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, from, to, status string
		want                   []string
	}{
		{"branches", "NONE", "NONE", "reported", []string{"2.0", "3.0"}},
		{"unknown", `"version":"1.0"`, `"version":"invalid"`, "unknown", []string{"0.5", "1.0", "2.0", "3.0"}},
		{"git", "ECOSYSTEM", "GIT", "unknown", nil},
		{"mismatch", `"ecosystem":"PyPI"},"ranges"`, `"ecosystem":"npm"},"ranges"`, "unknown", nil},
		{"no_fix", `"fixed"`, `"last_affected"`, "no_reported_fix", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := fixture(t, strings.ReplaceAll(fixturePackage, tc.from, tc.to))
			p := r.Results[0].Packages[0]
			f := advisoryFixes(p.Package, p.Vulnerabilities[0])
			if f.Status != tc.status || !reflect.DeepEqual(f.Versions, tc.want) {
				t.Fatalf("got %+v", f)
			}
		})
	}
}
func TestBatchAliasMerge(t *testing.T) {
	b := newBuilder()
	r := fixture(t, fixturePackage)
	b.add(request{Image: "one"}, response{Result: r})
	r.Results[0].Packages[0].Vulnerabilities[0].Details = strings.Repeat("discarded", 10000)
	b.add(request{Image: "one"}, response{Result: r})
	r.Results[0].Packages[0].Vulnerabilities[0].Summary = "conflicting retained summary"
	r.Results[0].Packages[0].Vulnerabilities[0].Aliases = []string{"CVE-2026-0"}
	b.add(request{Image: "three"}, response{Result: r})
	b.add(request{Image: "bad"}, failure("scan_error", "fixture"))
	out := b.finish()
	if len(out.Images) != 4 || len(out.Vulnerabilities) != 1 || out.Vulnerabilities[0].ID != "CVE-2026-0" {
		t.Fatal("incorrect batch images or merged vulnerability")
	}
	if *out.AdvisorySources[0].Modified != "2026-01-01T00:00:00.123456789Z" {
		t.Fatal("lost timestamp precision")
	}
}
func TestEmptyAndAllFailed(t *testing.T) {
	b := newBuilder()
	r := b.finish()
	if len(r.Images) != 0 {
		t.Fatal("empty")
	}
	b = newBuilder()
	b.add(request{Image: "bad"}, failure("scan_error", "bad"))
	r = b.finish()
	if r.Images[0].Status != "failed" || len(r.Findings) != 0 {
		t.Fatal("failed")
	}
}
func TestDistroSourceAndExtensionFacts(t *testing.T) {
	raw := `{"package":{"name":"binary","os_package_name":"source","version":"1:2.0-3ubuntu1","ecosystem":"Ubuntu:24.04"},"vulnerabilities":[{"id":"A","database_specific":{"severity":"HIGH","ignored":"drop"},"affected":[{"package":{"name":"source","ecosystem":"Ubuntu:24.04:Pro:LTS"},"ecosystem_specific":{"urgency":"high"},"severity":[{"type":"CVSS_V3","score":"vector"}],"ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"1:2.0-3ubuntu1"},{"fixed":"1:2.0-3ubuntu2"},{"last_affected":"99"},{"limit":"100"}]}]}]}]}`
	r := fixture(t, raw)
	p := r.Results[0].Packages[0]
	f := advisoryFixes(p.Package, p.Vulnerabilities[0])
	a := projectAdvisory(p.Vulnerabilities[0])
	if !reflect.DeepEqual(f.Versions, []string{"1:2.0-3ubuntu2"}) || len(f.Severities) != 1 || !reflect.DeepEqual(f.Urgencies, []string{"high"}) || a.DatabaseSeverity == nil || *a.DatabaseSeverity != "HIGH" {
		t.Fatalf("projection: %+v %+v", f, a)
	}
}
