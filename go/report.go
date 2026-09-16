package main

import (
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/google/osv-scalibr/semantic"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Compact reports contain relationships, not copies of full advisories. These
// structs also generate the Python schema, just like the upstream full result.
type scanResult struct {
	Image           string                 `json:"image"`
	Metadata        scanMetadata           `json:"metadata"`
	Vulnerabilities []vulnerabilitySummary `json:"vulnerabilities"`
	Packages        []packageSummary       `json:"packages"`
	Licenses        *licenseReport         `json:"licenses,omitempty"`
}

type fullScanData struct {
	models.VulnerabilityResults
	Image    string       `json:"image"`
	Metadata scanMetadata `json:"metadata"`
}

type severitySummary struct {
	Score  *float64 `json:"score"`
	Rating string   `json:"rating" jsonschema:"enum=unknown,enum=none,enum=low,enum=medium,enum=high,enum=critical"`
}

type vulnerabilitySummary struct {
	ID       string          `json:"id"`
	Aliases  []string        `json:"aliases"`
	Severity severitySummary `json:"severity"`
	Packages []string        `json:"packages"`
}

type packageSummary struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	InstalledVersion string           `json:"installed_version"`
	Ecosystem        string           `json:"ecosystem"`
	Vulnerabilities  []packageFinding `json:"vulnerabilities"`
}

type packageFinding struct {
	ID            string   `json:"id"`
	FixedVersions []string `json:"fixed_versions"`
}

type licenseReport struct {
	AllowedLicenses []string           `json:"allowed_licenses"`
	Violations      []licenseViolation `json:"violations"`
}

type licenseViolation struct {
	Package   string   `json:"package"`
	Licenses  []string `json:"licenses"`
	Forbidden []string `json:"forbidden"`
}

func unique(values []string) []string {
	slices.Sort(values)
	return slices.Compact(values)
}

func rating(score *float64) string {
	switch {
	case score == nil:
		return "unknown"
	case *score >= 9:
		return "critical"
	case *score >= 7:
		return "high"
	case *score >= 4:
		return "medium"
	case *score > 0:
		return "low"
	default:
		return "none"
	}
}

// Merge upstream alias groups across packages, preserving OSV's grouping rather
// than matching vulnerabilities again. Prefer CVE IDs as component names.
func vulnerabilityIDs(result models.VulnerabilityResults) map[string]string {
	parent := map[string]string{}
	var root func(string) string
	root = func(id string) string {
		if p, ok := parent[id]; !ok {
			parent[id] = id
		} else if p != id {
			parent[id] = root(p)
		}
		return parent[id]
	}
	for _, source := range result.Results {
		for _, pkg := range source.Packages {
			for _, group := range pkg.Groups {
				ids := group.Aliases // OSV includes the advisory IDs in this list.
				for _, id := range ids {
					a, b := root(ids[0]), root(id)
					if strings.HasPrefix(b, "CVE-") && !strings.HasPrefix(a, "CVE-") ||
						strings.HasPrefix(a, "CVE-") == strings.HasPrefix(b, "CVE-") && b < a {
						a, b = b, a
					}
					parent[b] = a
				}
			}
		}
	}
	for id := range parent {
		parent[id] = root(id)
	}
	return parent
}

func compactResults(result models.VulnerabilityResults, req request, metadata scanMetadata) *scanResult {
	report := &scanResult{Image: req.Image, Metadata: metadata, Vulnerabilities: []vulnerabilitySummary{}, Packages: []packageSummary{}}
	ids := vulnerabilityIDs(result)
	vulns := map[string]*vulnerabilitySummary{}
	packages := map[string]*packageSummary{}
	violations := map[string]*licenseViolation{}
	for _, source := range result.Results {
		for _, pkg := range source.Packages {
			if !req.AllPackages && len(pkg.Vulnerabilities) == 0 && len(pkg.LicenseViolations) == 0 {
				continue
			}
			info := pkg.Package
			key := url.PathEscape(info.Ecosystem) + "/" + url.PathEscape(info.Name) + "@" + url.PathEscape(info.Version)
			p := packages[key]
			if p == nil {
				p = &packageSummary{ID: key, Name: info.Name, InstalledVersion: info.Version,
					Ecosystem: info.Ecosystem, Vulnerabilities: []packageFinding{}}
				packages[key] = p
			}
			for _, group := range pkg.Groups {
				id := ids[group.IDs[0]]
				v := vulns[id]
				if v == nil {
					v = &vulnerabilitySummary{ID: id, Aliases: []string{}, Packages: []string{}}
					vulns[id] = v
				}
				v.Packages = append(v.Packages, key)
				if score, err := strconv.ParseFloat(group.MaxSeverity, 64); err == nil &&
					(v.Severity.Score == nil || score > *v.Severity.Score) {
					v.Severity.Score = &score
				}
				fixes := packageFixes(pkg, group.IDs)
				idx := slices.IndexFunc(p.Vulnerabilities, func(f packageFinding) bool { return f.ID == id })
				if idx < 0 {
					p.Vulnerabilities = append(p.Vulnerabilities, packageFinding{ID: id, FixedVersions: fixes})
				} else {
					p.Vulnerabilities[idx].FixedVersions = unique(append(p.Vulnerabilities[idx].FixedVersions, fixes...))
				}
			}
			if req.AllowedLicenses != nil && len(pkg.LicenseViolations) > 0 {
				l := violations[key]
				if l == nil {
					l = &licenseViolation{Package: key, Licenses: []string{}, Forbidden: []string{}}
					violations[key] = l
				}
				for _, license := range pkg.Licenses {
					l.Licenses = append(l.Licenses, string(license))
				}
				for _, license := range pkg.LicenseViolations {
					l.Forbidden = append(l.Forbidden, string(license))
				}
			}
		}
	}
	for alias, id := range ids {
		if v := vulns[id]; v != nil && alias != id {
			v.Aliases = append(v.Aliases, alias)
		}
	}
	for _, v := range vulns {
		slices.Sort(v.Aliases)
		v.Packages = unique(v.Packages)
		v.Severity.Rating = rating(v.Severity.Score)
		report.Vulnerabilities = append(report.Vulnerabilities, *v)
	}
	for _, p := range packages {
		slices.SortFunc(p.Vulnerabilities, func(a, b packageFinding) int { return strings.Compare(a.ID, b.ID) })
		report.Packages = append(report.Packages, *p)
	}
	slices.SortFunc(report.Vulnerabilities, func(a, b vulnerabilitySummary) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(report.Packages, func(a, b packageSummary) int { return strings.Compare(a.ID, b.ID) })
	if req.AllowedLicenses != nil {
		report.Licenses = &licenseReport{AllowedLicenses: unique(slices.Clone(req.AllowedLicenses)), Violations: []licenseViolation{}}
		for _, l := range violations {
			l.Licenses, l.Forbidden = unique(l.Licenses), unique(l.Forbidden)
			report.Licenses.Violations = append(report.Licenses.Violations, *l)
		}
		slices.SortFunc(report.Licenses.Violations, func(a, b licenseViolation) int { return strings.Compare(a.Package, b.Package) })
	}
	return report
}

// Report explicit fix events for this package, using Scalibr's ecosystem-aware
// ordering to exclude fixes older than the installed version. This is advisory
// presentation, not a second vulnerability matcher or an upgrade recommendation.
func packageFixes(pkg models.PackageVulns, ids []string) []string {
	fixes := []string{}
	installed, parseErr := semantic.Parse(pkg.Package.Version, pkg.Package.Ecosystem)
	for _, advisory := range pkg.Vulnerabilities {
		if !slices.Contains(ids, advisory.GetId()) {
			continue
		}
		for _, affected := range advisory.GetAffected() {
			eco := affected.GetPackage().GetEcosystem()
			if strings.HasPrefix(eco, "Ubuntu:") {
				eco = strings.ReplaceAll(strings.ReplaceAll(eco, ":Pro", ""), ":LTS", "")
			}
			if affected.GetPackage().GetName() != pkg.Package.Name || eco != pkg.Package.Ecosystem {
				continue
			}
			for _, r := range affected.GetRanges() {
				for _, event := range r.GetEvents() {
					fix := event.GetFixed()
					if fix == "" || r.GetType() == osvschema.Range_GIT {
						continue
					}
					if parseErr == nil {
						if order, err := installed.CompareStr(fix); err == nil && order >= 0 {
							continue
						}
					}
					fixes = append(fixes, fix)
				}
			}
		}
	}
	return unique(fixes)
}
