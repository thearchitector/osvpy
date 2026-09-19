package main

import (
	"encoding/json"
	"github.com/google/osv-scanner/v2/pkg/models"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestProjectionCanonicalizationPreservesInputs(t *testing.T) {
	r := fixture(t, `{"package":{"name":"example","version":"1.0","ecosystem":"PyPI"},
		"dep_groups":["z","a","z"],"licenses":["MIT","Apache-2.0","MIT"],
		"license_violations":["MIT","Apache-2.0","MIT"],
		"vulnerabilities":[{"id":"A","aliases":["Z","B","Z"],
		"severity":[{"type":"CVSS_V3","score":"z"},{"type":"CVSS_V3","score":"a"},{"type":"CVSS_V3","score":"z"}],
		"references":[{"type":"WEB","url":"z"},{"type":"WEB","url":"a"},{"type":"WEB","url":"z"}]}]}`)
	// Assign directly so this also exercises the upstream slice's full capacity.
	r.Results[0].Packages[0].DepGroups = []string{"z", "a", "z"}
	before, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var sink pendingImage
	projectImage(nil, request{AllPackages: true, AllowedLicenses: []string{}}, response{Result: r}, &sink)
	a := sink.occurrences[0].findings[0].advisory
	if !slices.Equal(a.Aliases, []string{"B", "Z"}) || len(a.Severities) != 2 ||
		a.Severities[0].Vector != "a" || a.Severities[1].Vector != "z" ||
		!reflect.DeepEqual(a.References, []reportReference{{"WEB", "a"}, {"WEB", "z"}}) {
		t.Fatalf("advisory canonicalization: %+v", a)
	}
	o := sink.occurrences[0]
	if !slices.Equal(o.context.DependencyGroups, []string{"a", "z"}) ||
		!slices.Equal(o.license.Licenses, []string{"Apache-2.0", "MIT"}) ||
		!slices.Equal(o.license.Violations, []string{"Apache-2.0", "MIT"}) {
		t.Fatalf("occurrence canonicalization: %+v", o)
	}
	a.Aliases[0] = "changed"
	o.context.DependencyGroups[0] = "changed"
	after, err := json.Marshal(r)
	if err != nil || string(before) != string(after) {
		t.Fatal("projection or output mutation changed upstream input")
	}
}

func TestAdvisoryCanonicalizationEmptyAndSingleton(t *testing.T) {
	for _, fields := range []string{"", `,"aliases":[],"severity":[],"references":[]`,
		`,"aliases":["B"],"severity":[{"type":"CVSS_V3","score":"v"}],"references":[{"type":"WEB","url":"u"}]`} {
		r := fixture(t, `{"vulnerabilities":[{"id":"A"`+fields+`}]}`)
		a := projectAdvisory(r.Results[0].Packages[0].Vulnerabilities[0])
		if strings.Contains(fields, `"B"`) {
			if !reflect.DeepEqual(a.Aliases, []string{"B"}) || len(a.Severities) != 1 ||
				a.Severities[0].Vector != "v" || !reflect.DeepEqual(a.References, []reportReference{{"WEB", "u"}}) {
				t.Fatalf("singleton values: %+v", a)
			}
		} else if a.Aliases != nil || a.Severities != nil || a.References != nil {
			t.Fatalf("empty projected slices must remain nil: %+v", a)
		}
	}
}

func TestAliasesRetainPackageSpecificFixes(t *testing.T) {
	r := fixture(t, fixturePackage)
	other := fixture(t, strings.ReplaceAll(fixturePackage, "example", "other")).Results[0].Packages[0]
	other.Package.Version = "2.0"
	other.Vulnerabilities[0].Id = "B"
	other.Vulnerabilities[0].Aliases = []string{"A"}
	r.Results[0].Packages = append(r.Results[0].Packages, other)
	b := newBuilder()
	b.add(request{Image: "fixture"}, response{Result: r})
	out := b.finish()
	if out.Vulnerabilities.Len() != 1 || out.Findings.Len() != 2 {
		t.Fatal("aliases must group without dropping package findings")
	}
	for i, want := range [][]string{{"2.0", "3.0"}, {"3.0"}} {
		fix := out.Findings.At(int(i)).Fix
		if !reflect.DeepEqual(out.fixAt(int(fix)).Versions, want) {
			t.Fatalf("package %d fixes: %v", i, out.fixAt(int(fix)))
		}
	}
}

func TestSeverityPreservesSourceAndVector(t *testing.T) {
	vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	r := fixture(t, strings.Replace(fixturePackage, `"id":"A"`, `"id":"A","severity":[{"type":"CVSS_V3","source":"NVD","score":"`+vector+`"}]`, 1))
	a := projectAdvisory(r.Results[0].Packages[0].Vulnerabilities[0])
	if len(a.Severities) != 1 || a.Severities[0] != (reportSeverity{"CVSS_V3", "NVD", vector}) {
		t.Fatalf("lost severity provenance: %+v", a.Severities)
	}
}

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
	b.add(request{Image: "one"}, response{Result: r})
	r.Results[0].Packages[0].Vulnerabilities[0].Summary = "conflicting retained summary"
	r.Results[0].Packages[0].Vulnerabilities[0].Aliases = []string{"CVE-2026-0"}
	b.add(request{Image: "three"}, response{Result: r})
	b.add(request{Image: "bad"}, failure("scan_error", "fixture"))
	out := b.finish()
	if out.Images.Len() != 4 || out.Vulnerabilities.Len() != 1 || out.vulnerabilityAt(int(0)).ID != "CVE-2026-0" {
		t.Fatal("incorrect batch images or merged vulnerability")
	}
	if *out.advisoryAt(int(0)).Modified != "2026-01-01T00:00:00.123456789Z" {
		t.Fatal("lost timestamp precision")
	}
}
func TestEmptyAndAllFailed(t *testing.T) {
	b := newBuilder()
	r := b.finish()
	if r.Images.Len() != 0 {
		t.Fatal("empty")
	}
	b = newBuilder()
	b.add(request{Image: "bad"}, failure("scan_error", "bad"))
	r = b.finish()
	if r.Images.At(int(0)).Status != "failed" || r.Findings.Len() != 0 {
		t.Fatal("failed")
	}
}

func TestUnknownLicenseAndAbsentAssessment(t *testing.T) {
	r := fixture(t, `{"package":{"name":"example","version":"1.0","ecosystem":"PyPI"}}`)
	b := newBuilder()
	b.add(request{Image: "unknown", AllowedLicenses: []string{}, AllPackages: true}, response{Result: r})
	b.add(request{Image: "disabled", AllPackages: true}, response{Result: r})
	out := b.finish()
	unknown := out.licenseAt(int(out.Occurrences.At(0).License))
	disabled := out.licenseAt(int(out.Occurrences.At(1).License))
	if unknown.Status != "unknown" || len(unknown.Licenses) != 0 || unknown.Policy == nil {
		t.Fatalf("missing licenses must remain unknown: %+v", unknown)
	}
	if disabled.Status != "not_evaluated" || disabled.Policy != nil {
		t.Fatalf("absent evaluation must remain distinct: %+v", disabled)
	}
	if len(out.Images.At(int(0)).Diagnostics) != 1 || out.Images.At(int(0)).Diagnostics[0].Code != "unknown_license" {
		t.Fatal("missing uncertainty diagnostic")
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
