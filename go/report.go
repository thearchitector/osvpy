package main

import (
	"cmp"
	"deps.dev/util/semver"
	"slices"
	"strings"
	"time"

	"github.com/google/osv-scalibr/semantic"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Only library-owned records cross the boundary. No upstream extension maps.
type reportPackage struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Ecosystem     string `json:"ecosystem"`
	Commit        string `json:"commit"`
	OSPackageName string `json:"os_package_name"`
	PURL          string `json:"purl"`
}
type reportSeverity struct {
	Type   string `json:"type"`
	Source string `json:"source"`
	Vector string `json:"vector"`
}
type reportReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}
type reportAdvisory struct {
	ID               string            `json:"id"`
	Aliases          []string          `json:"aliases,omitempty"`
	Summary          string            `json:"summary"`
	Modified         *string           `json:"modified"`
	Published        *string           `json:"published"`
	Withdrawn        *string           `json:"withdrawn"`
	Severities       []reportSeverity  `json:"severities,omitempty"`
	References       []reportReference `json:"references,omitempty"`
	DatabaseSeverity *string           `json:"database_severity"`
}
type reportVulnerability struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
}
type reportContext struct {
	Path             string   `json:"path"`
	SourceType       string   `json:"source_type"`
	Layer            *string  `json:"layer"`
	DependencyGroups []string `json:"dependency_groups,omitempty"`
}
type reportAssessment struct {
	Called      *bool  `json:"called"`
	Unimportant *bool  `json:"unimportant"`
	MaxSeverity string `json:"max_severity"`
}
type reportLicense struct {
	Licenses   []string `json:"licenses,omitempty"`
	Policy     []string `json:"policy,omitempty"`
	Violations []string `json:"violations,omitempty"`
	Status     string   `json:"status"`
}
type reportFix struct {
	Versions   []string         `json:"versions,omitempty"`
	Status     string           `json:"status"`
	Severities []reportSeverity `json:"severities,omitempty"`
	Urgencies  []string         `json:"urgencies,omitempty"`
}
type reportImage struct {
	Requested   string        `json:"requested"`
	Metadata    scanMetadata  `json:"metadata"`
	OS          *string       `json:"os"`
	Status      string        `json:"status"`
	Diagnostics []nativeError `json:"diagnostics,omitempty"`
}
type occurrenceRow struct{ Image, Package, Context, License uint32 }
type findingRow struct{ Occurrence, Advisory, Fix, Assessment, Vulnerability uint32 }

type reportStore struct {
	Indexes         []reportIndex         `json:"indexes"`
	Images          []reportImage         `json:"images,omitempty"`
	Packages        []reportPackage       `json:"packages,omitempty"`
	Vulnerabilities []reportVulnerability `json:"vulnerabilities,omitempty"`
	AdvisorySources []reportAdvisory      `json:"advisory_sources,omitempty"`
	Contexts        []reportContext       `json:"contexts,omitempty"`
	Assessments     []reportAssessment    `json:"assessments,omitempty"`
	Licenses        []reportLicense       `json:"licenses,omitempty"`
	Fixes           []reportFix           `json:"fixes,omitempty"`
	// Occurrences: image, package, context, license. Findings: occurrence,
	// advisory source, fix evidence, assessment, vulnerability group.
	Occurrences []occurrenceRow `json:"occurrences,omitempty"`
	Findings    []findingRow    `json:"findings,omitempty"`
}

func unique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	slices.Sort(values)
	return slices.Clone(slices.Compact(values))
}

func canonicalSeverities(values []reportSeverity) []reportSeverity {
	slices.SortFunc(values, func(a, b reportSeverity) int {
		return cmp.Or(strings.Compare(a.Type, b.Type), strings.Compare(a.Source, b.Source), strings.Compare(a.Vector, b.Vector))
	})
	return slices.Clone(slices.Compact(values))
}
func timestamp(t *timestamppb.Timestamp) *string {
	if t == nil {
		return nil
	}
	if err := t.CheckValid(); err != nil {
		panic("invalid upstream timestamp")
	}
	s := t.AsTime().Format(time.RFC3339Nano)
	return &s
}
func projectAdvisory(a *osvschema.Vulnerability) reportAdvisory {
	r := reportAdvisory{ID: a.GetId(), Aliases: unique(slices.Clone(a.GetAliases())), Summary: a.GetSummary(), Modified: timestamp(a.GetModified()), Published: timestamp(a.GetPublished()), Withdrawn: timestamp(a.GetWithdrawn())}
	for _, s := range a.GetSeverity() {
		r.Severities = append(r.Severities, reportSeverity{s.GetType().String(), s.GetSource().String(), s.GetScore()})
	}
	for _, ref := range a.GetReferences() {
		r.References = append(r.References, reportReference{ref.GetType().String(), ref.GetUrl()})
	}
	r.DatabaseSeverity = extensionString(a.GetDatabaseSpecific(), "severity")
	r.Severities = canonicalSeverities(r.Severities)
	slices.SortFunc(r.References, func(a, b reportReference) int {
		return cmp.Or(strings.Compare(a.Type, b.Type), strings.Compare(a.URL, b.URL))
	})
	r.References = slices.Clone(slices.Compact(r.References))
	return r
}

func extensionString(value *structpb.Struct, key string) *string {
	if field := value.GetFields()[key]; field != nil {
		if s, ok := field.Kind.(*structpb.Value_StringValue); ok {
			text := strings.Clone(s.StringValue)
			return &text
		}
	}
	return nil
}
func ecosystem(s string) string {
	if strings.HasPrefix(s, "Ubuntu:") {
		return strings.ReplaceAll(strings.ReplaceAll(s, ":Pro", ""), ":LTS", "")
	}
	return s
}

// Reject permissive/legacy parser fallbacks before using ecosystem ordering.
// Preserve their fixes as unknown rather than claiming supported ordering.
func versionKnown(version, eco string) bool {
	var system semver.System
	switch strings.SplitN(eco, ":", 2)[0] {
	case "PyPI":
		system = semver.PyPI
	case "npm":
		system = semver.NPM
	case "crates.io":
		system = semver.Cargo
	case "NuGet":
		system = semver.NuGet
	case "RubyGems":
		system = semver.RubyGems
	case "Packagist":
		system = semver.Composer
	case "Go":
		system = semver.Go
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
	case "Bitnami", "Bioconductor", "ConanCenter", "Docker Hardened Images", "GHC", "Hex", "Julia", "SwiftURL", "Pub":
		system = semver.DefaultSystem
	default:
		return version != ""
	}
	_, err := system.Parse(version)
	return err == nil
}
func advisoryFixes(pkg models.PackageInfo, a *osvschema.Vulnerability) reportFix {
	return packageFixes(pkg)(a)
}

func packageFixes(pkg models.PackageInfo) func(*osvschema.Vulnerability) reportFix {
	installed, parseErr := semantic.Parse(pkg.Version, ecosystem(pkg.Ecosystem))
	known := parseErr == nil && versionKnown(pkg.Version, pkg.Ecosystem)
	return func(a *osvschema.Vulnerability) reportFix {
		r := reportFix{Status: "no_reported_fix"}
		matched, unknown := false, false
		for _, affected := range a.GetAffected() {
			p := affected.GetPackage()
			if ecosystem(p.GetEcosystem()) != ecosystem(pkg.Ecosystem) || (p.GetName() != pkg.Name && (pkg.OSPackageName == "" || p.GetName() != pkg.OSPackageName)) {
				continue
			}
			matched = true
			for _, severity := range affected.GetSeverity() {
				r.Severities = append(r.Severities, reportSeverity{severity.GetType().String(), severity.GetSource().String(), severity.GetScore()})
			}
			if urgency := extensionString(affected.GetEcosystemSpecific(), "urgency"); urgency != nil {
				r.Urgencies = append(r.Urgencies, *urgency)
			}
			for _, rg := range affected.GetRanges() {
				if rg.GetType() != osvschema.Range_ECOSYSTEM && rg.GetType() != osvschema.Range_SEMVER {
					unknown = true
				}
				if rg.GetType() == osvschema.Range_GIT {
					unknown = true
					continue
				}
				for _, event := range rg.GetEvents() {
					fix := event.GetFixed()
					if fix == "" {
						continue
					}
					if !known || !versionKnown(fix, pkg.Ecosystem) {
						unknown = true
					} else if order, err := installed.CompareStr(fix); err != nil {
						unknown = true
					} else if order >= 0 {
						continue
					}
					r.Versions = append(r.Versions, fix)
				}
			}
		}
		r.Versions = unique(r.Versions)
		r.Urgencies = unique(r.Urgencies)
		r.Severities = canonicalSeverities(r.Severities)
		if len(r.Versions) > 0 {
			r.Status = "reported"
		}
		if !matched || unknown {
			r.Status = "unknown"
		}
		return r
	}
}
