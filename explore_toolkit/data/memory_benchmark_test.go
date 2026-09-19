// Injected into an isolated Go workspace by explore_toolkit.benchmark_memory.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// These are projected reporting facts, not a scanner/database workload. Repeat
// findings deliberately exercise raw relationship multiplicity before dedup.
func ingestMemoryWorkload(images, packages int, overlap bool) *batchBuilder {
	b := newBuilder()
	for image := range images {
		p := pendingImage{image: reportImage{Requested: fmt.Sprintf("image-%d", image), Status: "complete"}}
		for pkg := range packages {
			id := pkg
			if !overlap {
				id += image * packages
			}
			name, advisory, cve := fmt.Sprintf("package-%06d", id), fmt.Sprintf("A-%06d", id), fmt.Sprintf("CVE-2026-%06d", id)
			p.union([]string{advisory, cve})
			p.occurrence(reportPackage{Name: name, Version: "1.0", Ecosystem: "PyPI"},
				reportContext{Path: "/packages/" + name, DependencyGroups: []string{"runtime"}},
				reportLicense{Status: "noncompliant", Licenses: []string{"MIT"}, Policy: []string{}, Violations: []string{"MIT"}})
			a := reportAdvisory{ID: advisory, Aliases: []string{cve}, Summary: strings.Repeat("advisory detail ", 32),
				Severities: []reportSeverity{{Type: "CVSS_V3", Vector: "vector"}},
				References: []reportReference{{Type: "WEB", URL: "https://example.test/" + advisory}}}
			for range 4 {
				p.finding(&a, reportFix{Status: "reported", Versions: []string{"2.0"}}, reportAssessment{MaxSeverity: "HIGH"})
			}
		}
		b.merge(p)
	}
	return b
}

// A benchmark-only streaming serialization of every logical table and every
// relationship. This is not a public export format or a Python allocation model.
// The report stays alive throughout, matching the immutable query lifecycle.
func exportMemoryWorkload(r *reportStore, output io.Writer) error {
	encoder := json.NewEncoder(output)
	tables := []struct {
		count int
		row   func(int) any
	}{
		{r.Images.Len(), func(i int) any { return r.Images.At(i) }},
		{r.Packages.Len(), func(i int) any { return r.packageAt(i) }},
		{r.Vulnerabilities.Len(), func(i int) any { return r.vulnerabilityAt(i) }},
		{r.AdvisorySources.Len(), func(i int) any { return r.advisoryAt(i) }},
		{r.Contexts.Len(), func(i int) any { return r.contextAt(i) }},
		{r.Assessments.Len(), func(i int) any { return r.assessmentAt(i) }},
		{r.Licenses.Len(), func(i int) any { return r.licenseAt(i) }},
		{r.Fixes.Len(), func(i int) any { return r.fixAt(i) }},
		{r.Occurrences.Len(), func(i int) any { return r.Occurrences.At(i) }},
		{r.Findings.Len(), func(i int) any { return r.Findings.At(i) }},
		{r.AdvisoryVulnerabilities.Len(), func(i int) any { return r.AdvisoryVulnerabilities.At(i) }},
	}
	for _, table := range tables {
		for row := range table.count {
			if err := encoder.Encode(table.row(row)); err != nil {
				return err
			}
		}
	}
	var edge struct{ Index, Key, Member uint32 }
	for slot, index := range r.Indexes {
		edge.Index = uint32(slot)
		for key := 0; key+1 < index.Offsets.Len(); key++ {
			edge.Key = uint32(key)
			start, end := *index.Offsets.At(key), *index.Offsets.At(key + 1)
			for member := start; member < end; member++ {
				edge.Member = member
				if !index.Range {
					edge.Member = *index.Members.At(int(member))
				}
				if err := encoder.Encode(&edge); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func observeHeapPeak(peak *atomic.Uint64) {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	for previous := peak.Load(); stats.HeapAlloc > previous; previous = peak.Load() {
		if peak.CompareAndSwap(previous, stats.HeapAlloc) {
			break
		}
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

func BenchmarkReportLifecycle(b *testing.B) {
	for _, workload := range []struct {
		name    string
		overlap bool
	}{{"fully_overlapping", true}, {"no_overlap", false}} {
		b.Run(workload.name, func(b *testing.B) {
			b.ReportAllocs()
			var peak atomic.Uint64
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				runtime.GC()
				stop, done := make(chan struct{}), make(chan struct{})
				go func() {
					defer close(done)
					ticker := time.NewTicker(time.Millisecond)
					defer ticker.Stop()
					for {
						observeHeapPeak(&peak)
						select {
						case <-stop:
							return
						case <-ticker.C:
						}
					}
				}()
				b.StartTimer()
				builder := ingestMemoryWorkload(10, 2000, workload.overlap)
				observeHeapPeak(&peak)
				report := builder.finish()
				observeHeapPeak(&peak)
				err := exportMemoryWorkload(&report, io.Discard)
				observeHeapPeak(&peak)
				b.StopTimer()
				close(stop)
				<-done
				runtime.KeepAlive(report)
				if err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(peak.Load()), "sampled-heap-peak-B")
		})
	}
}
