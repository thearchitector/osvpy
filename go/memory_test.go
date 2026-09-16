package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/opencontainers/go-digest"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
)

// Production-schema fixture: 2,000 occurrences, 1,400 using 140 shared
// advisories, 600 using individual advisories. No acquisition/database work.
func memoryFixture(image int, mode string) models.VulnerabilityResults {
	// Use the same full-information template as the historical batch probe.
	raw, err := os.ReadFile("../tests/data/complete_response.json")
	if err != nil {
		panic(err)
	}
	var envelope struct {
		Result models.VulnerabilityResults `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		panic(err)
	}
	result := envelope.Result
	template := result.Results[0].Packages[0]
	result.Results[0].Packages = nil
	result.ImageMetadata.LayerMetadata[0].DiffID = digest.Digest(fmt.Sprintf("sha256:layer-%d", image))
	advisory := map[int]*osvschema.Vulnerability{}
	for p := range 2000 {
		identity := p
		if mode == "disjoint" || mode == "partial" && p >= 1400 {
			identity += image * 2000
		}
		name := fmt.Sprintf("package-%d", identity)
		key := p % 140
		if p >= 1400 {
			key = p - 1400 + 140
		}
		a := advisory[key]
		if a == nil {
			id := fmt.Sprintf("SOURCE-%d", key)
			if mode == "disjoint" || mode == "alias" || mode == "partial" && p >= 1400 {
				id = fmt.Sprintf("SOURCE-%d-%d", image, key)
			}
			alias := fmt.Sprintf("CVE-2026-%05d", key)
			if mode == "disjoint" {
				alias = fmt.Sprintf("CVE-2026-%05d", image*740+key)
			}
			a = proto.Clone(template.Vulnerabilities[0]).(*osvschema.Vulnerability)
			a.Id = id
			a.Aliases = []string{alias}
			a.Affected = nil
			if mode == "large" {
				a.Details = strings.Repeat("discarded details ", 4096)
			}
			advisory[key] = a
		}
		affected := proto.Clone(template.Vulnerabilities[0].Affected[0]).(*osvschema.Affected)
		affected.Package.Name = name
		affected.Package.Purl = "pkg:deb/ubuntu/" + name + "@1.0"
		a.Affected = append(a.Affected, affected)
		pkg := template
		pkg.Package.Name = name
		pkg.Vulnerabilities = []*osvschema.Vulnerability{a}
		pkg.Groups = []models.GroupInfo{{IDs: []string{a.Id}, Aliases: append([]string{a.Id}, a.Aliases...), MaxSeverity: "9.8", ExperimentalAnalysis: map[string]models.AnalysisInfo{a.Id: {Called: true}}}}
		pkg.LicenseViolations = nil
		if image%2 == 1 {
			pkg.LicenseViolations = []models.License{"GPL-3.0"}
		}
		if mode == "assessments" {
			pkg.Licenses = []models.License{"MIT"}
			if image%2 == 1 {
				pkg.LicenseViolations = []models.License{"MIT"}
			}
			pkg.Groups[0].ExperimentalAnalysis = map[string]models.AnalysisInfo{a.Id: {Called: image%2 == 0}}
		}
		result.Results[0].Packages = append(result.Results[0].Packages, pkg)
	}
	return result
}

func TestProductionMemoryFixtures(t *testing.T) {
	dir := os.Getenv("OSVPY_MEMORY_DIR")
	if dir == "" {
		t.Skip("production memory fixture generation not requested")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	stats := []map[string]any{}
	for _, mode := range []string{"single", "identical", "partial", "disjoint", "alias", "assessments", "large", "failures"} {
		count := 10
		if mode == "single" {
			count = 1
		}
		for _, independent := range []bool{false, true} {
			label := mode
			if independent {
				label += "-independent"
			}
			runtime.GC()
			var base, peak, overlap runtime.MemStats
			runtime.ReadMemStats(&base)
			start := time.Now()
			b := newBuilder()
			var buildTime, encodeTime time.Duration
			var maxC int
			emit := func(index int) {
				stamp := time.Now()
				r := b.finish()
				runtime.ReadMemStats(&overlap)
				if overlap.HeapAlloc > peak.HeapAlloc {
					peak = overlap
				}
				buildTime += time.Since(stamp)
				w := &directWriter{}
				stamp = time.Now()
				if err := encodeReport(w, r); err != nil {
					w.free()
					t.Fatal(err)
				}
				encodeTime += time.Since(stamp)
				maxC = max(maxC, w.capacity)
				raw := unsafe.Slice((*byte)(w.p), w.n)
				path := filepath.Join(dir, fmt.Sprintf("%s-%d.msgpack", label, index))
				if err := os.WriteFile(path, raw, 0644); err != nil {
					w.free()
					t.Fatal(err)
				}
				w.free()
			}
			for i := 0; i < count; i++ {
				stamp := time.Now()
				req := request{Image: fmt.Sprintf("fixture-%d", i), AllPackages: true}
				if mode == "assessments" {
					req.AllowedLicenses = []string{"MIT"}
					if i%2 == 1 {
						req.AllowedLicenses = []string{}
					}
				}
				if mode == "failures" && i%3 == 1 {
					b.add(req, failure("scan_error", "synthetic acquisition failure"))
				} else {
					b.add(req, response{Result: memoryFixture(i, mode)})
				}
				buildTime += time.Since(stamp)
				runtime.ReadMemStats(&overlap)
				if overlap.HeapAlloc > peak.HeapAlloc {
					peak = overlap
				}
				if independent {
					emit(i)
					b = newBuilder()
				}
			}
			if !independent {
				emit(0)
			}
			runtime.GC()
			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			stats = append(stats, map[string]any{"case": label, "seconds": time.Since(start).Seconds(), "construction_seconds": buildTime.Seconds(), "encode_seconds": encodeTime.Seconds(), "sampled_go_peak_bytes": int64(peak.HeapAlloc) - int64(base.HeapAlloc), "finish_go_bytes": int64(overlap.HeapAlloc) - int64(base.HeapAlloc), "max_c_capacity": maxC, "post_release_go_bytes": int64(after.HeapAlloc) - int64(base.HeapAlloc)})
		}
	}
	raw, _ := json.MarshalIndent(stats, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "native.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
}
