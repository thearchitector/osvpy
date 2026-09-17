package main

import (
	"archive/zip"
	"fmt"
	"io"
	"path/filepath"

	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/google/osv-scanner/v2/pkg/models"
)

// Match the pinned scanner's filter annotator and SCALIBR osvlocal matcher.
// Full inventory also contains reattached unscannable packages, which must not
// cause spurious database requirements. Revisit these rules on upstream upgrades.
func offlineEcosystem(p models.PackageInfo) string {
	eco, err := osvecosystem.Parse(p.Ecosystem)
	if err != nil || (eco.IsEmpty() || p.Name == "" || p.Version == "") && p.Commit == "" {
		return ""
	}
	if (string(eco.Ecosystem) == "Maven" && p.Name == "unknown") || (p.Commit != "" && len(p.Commit) < 40) {
		return ""
	}
	// The matcher uses inventory ecosystem, including its GIT fallback, rather
	// than the display ecosystem potentially overridden by scanner metadata.
	if p.Inventory != nil {
		eco = p.Inventory.Ecosystem()
	}
	if eco.IsEmpty() || eco.String() == "GIT" {
		if p.Version == "" { // Commit-only matching requires the online API.
			return ""
		}
		return "GIT"
	}
	return string(eco.Ecosystem)
}

func validateOfflineDatabases(base string, result models.VulnerabilityResults) error {
	checked := make(map[string]bool)
	for _, source := range result.Results {
		for _, pkg := range source.Packages {
			eco := offlineEcosystem(pkg.Package)
			if eco == "" || checked[eco] {
				continue
			}
			checked[eco] = true
			path := filepath.Join(base, "osv-scalibr", eco, "all.zip")
			if err := validateDatabaseArchive(path); err != nil {
				return fmt.Errorf("offline database for %s unavailable: %w", eco, err)
			}
		}
	}
	return nil
}

// Verify ZIP structure and checksums, not advisory JSON semantics. Database
// files must remain unchanged for the duration of all active scans.
func validateDatabaseArchive(path string) error {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer archive.Close()
	for _, entry := range archive.File {
		reader, err := entry.Open()
		if err != nil {
			return err
		}
		_, readErr := io.Copy(io.Discard, reader)
		closeErr := reader.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
