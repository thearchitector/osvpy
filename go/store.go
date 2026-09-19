package main

import (
	"cmp"
	"context"
	"math"
	"slices"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Comparable compact keys use Go's typed equality, including on hash collisions.
type table[T comparable] struct{ ids map[T]int }

func (t *table[T]) intern(dst *slabs[T], value T) int {
	if i, ok := t.ids[value]; ok {
		return i
	}
	if t.ids == nil {
		t.ids = make(map[T]int)
	}
	i := dst.Append(value)
	t.ids[value] = i
	return i
}

type batchBuilder struct {
	ctx             context.Context
	report          reportStore
	packages        table[storedPackage]
	payload         payloadBuilder
	advisory        table[storedAdvisory]
	imageAdvisories map[*reportAdvisory]int
	context         table[storedContext]
	assessment      table[storedAssessment]
	license         table[storedLicense]
	fix             table[storedFix]
	aliasID         map[string]uint32
	names           []string
	parent          []uint32
}

func newBuilder() *batchBuilder {
	return &batchBuilder{aliasID: make(map[string]uint32)}
}
func checked(v int) uint32 {
	if v < 0 || uint64(v) > math.MaxUint32 {
		panic("report_overflow")
	}
	return uint32(v)
}
func (b *batchBuilder) internAlias(name string) uint32 {
	if id, ok := b.aliasID[name]; ok {
		return id
	}
	checked(len(b.names) + 1)
	id := checked(len(b.names))
	b.aliasID[name] = id
	b.names = append(b.names, name)
	b.parent = append(b.parent, id)
	return id
}
func (b *batchBuilder) root(id uint32) uint32 {
	// Iterative path halving also handles long chains without growing the stack.
	for b.parent[id] != id {
		b.parent[id] = b.parent[b.parent[id]]
		id = b.parent[id]
	}
	return id
}
func preferred(a, b string) bool {
	ac, bc := strings.HasPrefix(a, "CVE-"), strings.HasPrefix(b, "CVE-")
	return ac && !bc || ac == bc && a < b
}
func (b *batchBuilder) union(ids []string) {
	if len(ids) == 0 {
		return
	}
	checkContext(b.ctx)
	a := b.root(b.internAlias(ids[0]))
	for _, id := range ids[1:] {
		checkContext(b.ctx)
		c := b.root(b.internAlias(id))
		if preferred(b.names[c], b.names[a]) {
			a, c = c, a
		}
		b.parent[c] = a
	}
}
func projectImage(cancelContext context.Context, req request, resp response, sink projectionSink) reportImage {
	im := reportImage{Requested: req.Image, Metadata: resp.Metadata, Status: "complete"}
	if resp.Error != nil {
		im.Status = "failed"
		if im.Metadata.ScannerVersion == "" {
			im.Metadata = scanMetadata{ScannerVersion: scannerVersion, AllPackages: req.AllPackages, Languages: req.Languages}
		}
		im.Diagnostics = append(im.Diagnostics, *resp.Error)
		return im
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
	local := map[*osvschema.Vulnerability]*reportAdvisory{}
	for _, source := range result.Results {
		if len(source.ExperimentalPES) > 0 {
			diagnostic("unsupported_assessment", "Package exploitability signals are not represented")
		}
		for _, pkg := range source.Packages {
			checkContext(cancelContext)
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
			ctx := reportContext{Path: source.Source.Path, SourceType: string(source.Source.Type), DependencyGroups: uniqueCopy(pkg.DepGroups)}
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
			lic := reportLicense{Status: "not_evaluated", Policy: req.AllowedLicenses}
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
			sink.occurrence(rp, ctx, lic)
			for _, group := range pkg.Groups {
				sink.union(append(slices.Clone(group.IDs), group.Aliases...))
			}
			groupsByID := make(map[string][]int, len(pkg.Vulnerabilities))
			for i, g := range pkg.Groups {
				for _, id := range g.IDs {
					groupsByID[id] = append(groupsByID[id], i)
				}
			}
			projectFix := packageFixes(p)
			for _, a := range pkg.Vulnerabilities {
				checkContext(cancelContext)
				if a == nil || a.GetId() == "" {
					diagnostic("unsupported_advisory", "Advisory has no source identifier")
					continue
				}
				ai, ok := local[a]
				if !ok {
					value := projectAdvisory(a)
					ai = &value
					local[a] = ai
				}
				sink.union(append([]string{a.GetId()}, a.GetAliases()...))
				fix := projectFix(a)
				linked := false
				for _, gi := range groupsByID[a.GetId()] {
					g := pkg.Groups[gi]
					linked = true
					assess := reportAssessment{MaxSeverity: g.MaxSeverity}
					if v, ok := g.ExperimentalAnalysis[a.GetId()]; ok {
						assess.Called = &v.Called
						assess.Unimportant = &v.Unimportant
					}
					sink.finding(ai, fix, assess)
				}
				if !linked {
					diagnostic("missing_assessment", "Advisory has no upstream group assessment")
					sink.finding(ai, fix, reportAssessment{})
				}
			}
		}
	}
	return im
}

type projectionSink interface {
	occurrence(reportPackage, reportContext, reportLicense)
	finding(*reportAdvisory, reportFix, reportAssessment)
	union([]string)
}

// Reordering holds only projected reporting facts, never upstream inventories,
// protobuf catalogs, or parsed database records. These are transient facts, not
// independently finalized report stores.
type pendingImage struct {
	image       reportImage
	occurrences []pendingOccurrence
	aliases     [][]string
}
type pendingOccurrence struct {
	pkg      reportPackage
	context  reportContext
	license  reportLicense
	findings []pendingFinding
}
type pendingFinding struct {
	advisory   *reportAdvisory
	fix        reportFix
	assessment reportAssessment
}

func (p *pendingImage) occurrence(pkg reportPackage, ctx reportContext, lic reportLicense) {
	p.occurrences = append(p.occurrences, pendingOccurrence{pkg: pkg, context: ctx, license: lic})
}
func (p *pendingImage) finding(advisory *reportAdvisory, fix reportFix, assessment reportAssessment) {
	o := &p.occurrences[len(p.occurrences)-1]
	o.findings = append(o.findings, pendingFinding{advisory, fix, assessment})
}
func (p *pendingImage) union(ids []string) { p.aliases = append(p.aliases, ids) }

func (b *batchBuilder) occurrence(pkg reportPackage, ctx reportContext, lic reportLicense) {
	checkContext(b.ctx)
	pi := b.packages.intern(&b.report.Packages, b.packPackage(pkg))
	ci := b.context.intern(&b.report.Contexts, b.packContext(ctx))
	li := b.license.intern(&b.report.Licenses, b.packLicense(lic))
	checked(b.report.Occurrences.Len() + 1)
	b.report.Occurrences.Append(occurrenceRow{checked(b.report.Images.Len()), checked(pi), checked(ci), checked(li)})
}
func (b *batchBuilder) finding(advisory *reportAdvisory, fix reportFix, assessment reportAssessment) {
	checkContext(b.ctx)
	ai, ok := b.imageAdvisories[advisory]
	if !ok {
		ai = b.advisory.intern(&b.report.AdvisorySources, b.packAdvisory(*advisory))
		b.imageAdvisories[advisory] = ai
	}
	fi := b.fix.intern(&b.report.Fixes, b.packFix(fix))
	si := b.assessment.intern(&b.report.Assessments, b.packAssessment(assessment))
	checked(b.report.Findings.Len() + 1)
	b.report.Findings.Append(findingRow{checked(b.report.Occurrences.Len() - 1), checked(ai), checked(fi), checked(si)})
}
func (b *batchBuilder) add(req request, resp response) {
	b.imageAdvisories = make(map[*reportAdvisory]int)
	defer func() { b.imageAdvisories = nil }()
	im := projectImage(b.ctx, req, resp, b)
	b.report.Images.Append(im)
}
func (b *batchBuilder) merge(p pendingImage) {
	b.imageAdvisories = make(map[*reportAdvisory]int)
	defer func() { b.imageAdvisories = nil }()
	for _, ids := range p.aliases {
		b.union(ids)
	}
	for _, o := range p.occurrences {
		b.occurrence(o.pkg, o.context, o.license)
		for _, f := range o.findings {
			b.finding(f.advisory, f.fix, f.assessment)
		}
	}
	b.report.Images.Append(p.image)
}
func (b *batchBuilder) finishAliases() {
	checkContext(b.ctx)
	counts := make([]uint32, len(b.names))
	var roots []uint32
	for id := range b.names {
		checkContext(b.ctx)
		root := b.root(uint32(id))
		b.parent[id] = root
		if counts[root] == 0 {
			roots = append(roots, root)
		}
		counts[root]++ // Total aliases was checked during interning.
	}
	slices.SortFunc(roots, func(a, c uint32) int { return cmp.Compare(b.names[a], b.names[c]) })
	offsets := make([]uint32, len(counts)+1)
	for id, count := range counts {
		checkContext(b.ctx)
		offsets[id+1] = offsets[id] + count
		counts[id] = offsets[id] // Reuse counts as write cursors.
	}
	members := make([]uint32, len(b.names))
	for id, root := range b.parent {
		checkContext(b.ctx)
		members[counts[root]] = uint32(id)
		counts[root]++
	}
	vulnerabilityByAlias := make([]uint32, len(b.names))
	aliases := make([]string, 0)
	for _, root := range roots {
		checkContext(b.ctx)
		checked(b.report.Vulnerabilities.Len() + 1)
		vi := checked(b.report.Vulnerabilities.Len())
		aliases = aliases[:0]
		for _, id := range members[offsets[root]:offsets[root+1]] {
			checkContext(b.ctx)
			vulnerabilityByAlias[id] = vi
			if id != root {
				aliases = append(aliases, b.names[id])
			}
		}
		slices.Sort(aliases)
		b.report.Vulnerabilities.Append(b.packVulnerability(reportVulnerability{b.names[root], aliases}))
		clear(aliases) // The packed payload owns its strings and words.
	}
	for i := 0; i < b.report.AdvisorySources.Len(); i++ {
		checkContext(b.ctx)
		var vi uint32
		if id, ok := b.aliasID[b.report.stringAt(b.report.AdvisorySources.At(i).ID)]; ok {
			vi = vulnerabilityByAlias[id]
		}
		b.report.AdvisoryVulnerabilities.Append(vi)
	}
	b.aliasID, b.names, b.parent = nil, nil, nil
}

func (b *batchBuilder) finish() reportStore {
	b.finishAliases()
	// Transfer ownership and drop all ingestion-only maps before allocating
	// indexes. This makes them collectible, without promising immediate RSS
	// reduction or forcing a global garbage collection.
	r, ctx := b.report, b.ctx
	*b = batchBuilder{}
	r.buildIndexes(ctx)
	return r
}
