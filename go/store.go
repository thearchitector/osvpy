package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math"
	"slices"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type table[T any] struct{ hashes map[[32]byte][]int }

func (t *table[T]) intern(dst *[]T, value T) int {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(raw)
	if t.hashes == nil {
		t.hashes = map[[32]byte][]int{}
	}
	for _, i := range t.hashes[h] {
		old, err := json.Marshal((*dst)[i])
		if err != nil {
			panic(err)
		}
		if bytes.Equal(raw, old) {
			return i
		}
	}
	i := len(*dst)
	checked(i)
	*dst = append(*dst, value)
	t.hashes[h] = append(t.hashes[h], i)
	return i
}

type batchBuilder struct {
	report     reportStore
	packages   map[reportPackage]int
	advisory   table[reportAdvisory]
	context    table[reportContext]
	assessment table[reportAssessment]
	license    table[reportLicense]
	fix        table[reportFix]
	parent     map[string]string
}

func newBuilder() *batchBuilder {
	return &batchBuilder{report: reportStore{ABIVersion: 4, SchemaVersion: 2}, packages: map[reportPackage]int{}, parent: map[string]string{}}
}
func checked(v int) uint32 {
	if v < 0 || uint64(v) > math.MaxUint32 {
		panic("report_overflow")
	}
	return uint32(v)
}
func appendRow(b []byte, values ...int) []byte {
	checked(len(b) + len(values)*4)
	for _, v := range values {
		b = binary.LittleEndian.AppendUint32(b, checked(v))
	}
	return b
}
func at(b []byte, row, width, col int) int {
	return int(binary.LittleEndian.Uint32(b[(row*width+col)*4:]))
}
func (b *batchBuilder) root(id string) string {
	p, ok := b.parent[id]
	if !ok {
		b.parent[id] = id
		return id
	}
	if p != id {
		b.parent[id] = b.root(p)
	}
	return b.parent[id]
}
func preferred(a, b string) bool {
	ac, bc := strings.HasPrefix(a, "CVE-"), strings.HasPrefix(b, "CVE-")
	return ac && !bc || ac == bc && a < b
}
func (b *batchBuilder) union(ids []string) {
	if len(ids) == 0 {
		return
	}
	a := b.root(ids[0])
	for _, id := range ids[1:] {
		c := b.root(id)
		if preferred(c, a) {
			a, c = c, a
		}
		b.parent[c] = a
	}
}
func (b *batchBuilder) add(req request, resp response) {
	ii := len(b.report.Images)
	checked(ii)
	im := reportImage{Requested: req.Image, Metadata: resp.Metadata, Status: "complete"}
	if resp.Error != nil {
		im.Status = "failed"
		if im.Metadata.ScannerVersion == "" {
			im.Metadata = scanMetadata{ScannerVersion: scannerVersion, Source: req.Source, Offline: req.Offline, AllPackages: req.AllPackages, DatabasePath: req.DatabasePath}
		}
		im.Diagnostics = append(im.Diagnostics, *resp.Error)
		b.report.Images = append(b.report.Images, im)
		return
	}
	result := resp.Result
	diagnostic := func(code, message string) {
		for _, d := range im.Diagnostics {
			if d.Code == code {
				return
			}
		}
		im.Diagnostics = append(im.Diagnostics, nativeError{code, message})
	}
	if result.ImageMetadata != nil {
		os := strings.Clone(result.ImageMetadata.OS)
		im.OS = &os
	}
	if len(result.ExperimentalGenericFindings) > 0 {
		diagnostic("unsupported_findings", "Generic upstream findings are not represented")
	}
	// Pointer memoization is image-local and never keeps an upstream graph alive.
	local := map[*osvschema.Vulnerability]int{}
	for _, source := range result.Results {
		if len(source.ExperimentalPES) > 0 {
			diagnostic("unsupported_assessment", "Package exploitability signals are not represented")
		}
		for _, pkg := range source.Packages {
			if pkg.Package.Deprecated {
				diagnostic("unsupported_deprecation", "Package deprecation is outside vulnerability/license reporting")
			}
			if !req.AllPackages && len(pkg.Vulnerabilities) == 0 && len(pkg.LicenseViolations) == 0 && !(req.AllowedLicenses != nil && len(pkg.Licenses) == 0) {
				continue
			}
			p := pkg.Package
			rp := reportPackage{Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem, Commit: p.Commit, OSPackageName: p.OSPackageName}
			if p.Inventory != nil {
				if u := p.Inventory.PURL(); u != nil {
					rp.PURL = u.String()
				}
				if len(p.Inventory.ExploitabilitySignals) > 0 {
					diagnostic("unsupported_assessment", "Package exploitability signals are not represented")
				}
			}
			pi, ok := b.packages[rp]
			if !ok {
				pi = len(b.report.Packages)
				checked(pi)
				b.report.Packages = append(b.report.Packages, rp)
				b.packages[rp] = pi
			}
			ctx := reportContext{Path: source.Source.Path, SourceType: string(source.Source.Type), DependencyGroups: unique(slices.Clone(pkg.DepGroups))}
			if p.Inventory != nil && p.Inventory.Location.PathOrEmpty() != "" {
				ctx.Path = p.Inventory.Location.PathOrEmpty()
			}
			if p.ImageOrigin != nil && result.ImageMetadata != nil {
				li := p.ImageOrigin.Index
				if li >= 0 && li < len(result.ImageMetadata.LayerMetadata) {
					s := string(result.ImageMetadata.LayerMetadata[li].DiffID)
					ctx.Layer = &s
				} else {
					diagnostic("unknown_layer", "Package layer index is unavailable")
				}
			}
			ci := b.context.intern(&b.report.Contexts, ctx)
			lic := reportLicense{Status: "not_evaluated", Policy: unique(slices.Clone(req.AllowedLicenses))}
			for _, l := range pkg.Licenses {
				lic.Licenses = append(lic.Licenses, string(l))
			}
			for _, l := range pkg.LicenseViolations {
				lic.Violations = append(lic.Violations, string(l))
			}
			lic.Licenses = unique(lic.Licenses)
			lic.Violations = unique(lic.Violations)
			if req.AllowedLicenses != nil {
				lic.Status = "compliant"
				if len(lic.Licenses) == 0 {
					lic.Status = "unknown"
					diagnostic("unknown_license", "License assessment is incomplete")
				} else if len(lic.Violations) > 0 {
					lic.Status = "noncompliant"
				}
			}
			li := b.license.intern(&b.report.Licenses, lic)
			oi := len(b.report.Occurrences) / 16
			b.report.Occurrences = appendRow(b.report.Occurrences, ii, pi, ci, li)
			for _, group := range pkg.Groups {
				b.union(append(slices.Clone(group.IDs), group.Aliases...))
			}
			for _, a := range pkg.Vulnerabilities {
				if a == nil || a.GetId() == "" {
					diagnostic("unsupported_advisory", "Advisory has no source identifier")
					continue
				}
				ai, ok := local[a]
				if !ok {
					ai = b.advisory.intern(&b.report.AdvisorySources, projectAdvisory(a))
					local[a] = ai
				}
				b.union(append([]string{a.GetId()}, a.GetAliases()...))
				fi := b.fix.intern(&b.report.Fixes, advisoryFixes(p, a))
				linked := false
				for _, g := range pkg.Groups {
					if !slices.Contains(g.IDs, a.GetId()) {
						continue
					}
					linked = true
					assess := reportAssessment{MaxSeverity: g.MaxSeverity}
					if v, ok := g.ExperimentalAnalysis[a.GetId()]; ok {
						assess.Called = &v.Called
						assess.Unimportant = &v.Unimportant
					}
					si := b.assessment.intern(&b.report.Assessments, assess)
					b.report.Findings = appendRow(b.report.Findings, oi, ai, fi, si, 0)
				}
				if !linked {
					diagnostic("missing_assessment", "Advisory has no upstream group assessment")
					si := b.assessment.intern(&b.report.Assessments, reportAssessment{})
					b.report.Findings = appendRow(b.report.Findings, oi, ai, fi, si, 0)
				}
			}
		}
	}
	b.report.Images = append(b.report.Images, im)
}
func (b *batchBuilder) finish() reportStore {
	groups := map[string][]string{}
	for id := range b.parent {
		root := b.root(id)
		groups[root] = append(groups[root], id)
	}
	roots := make([]string, 0, len(groups))
	for id := range groups {
		roots = append(roots, id)
	}
	slices.Sort(roots)
	ids := map[string]int{}
	for _, root := range roots {
		ids[root] = len(b.report.Vulnerabilities)
		aliases := unique(groups[root])
		aliases = slices.DeleteFunc(aliases, func(s string) bool { return s == root })
		b.report.Vulnerabilities = append(b.report.Vulnerabilities, reportVulnerability{root, aliases})
	}
	for i := 0; i < len(b.report.Findings)/20; i++ {
		ai := at(b.report.Findings, i, 5, 1)
		vi := ids[b.root(b.report.AdvisorySources[ai].ID)]
		binary.LittleEndian.PutUint32(b.report.Findings[i*20+16:], checked(vi))
	}
	r := b.report
	*b = batchBuilder{}
	return r
}
