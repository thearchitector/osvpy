package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Keep successful scans and upstream error logging running concurrently. Neither
// this test nor execute may acquire an admission lock: run with go test -race.
func TestConcurrentOfflineScans(t *testing.T) {
	valid := offlineRequest(t, "3.0.0-1")
	bad := offlineRequest(t, "3.0.0-1")
	if err := os.Remove(filepath.Join(bad.DatabasePath, "osv-scalibr", "Ubuntu", "all.zip")); err != nil {
		t.Fatal(err)
	}
	inputs := make([]request, 8)
	for i := range inputs {
		inputs[i] = offlineRequest(t, fmt.Sprintf("3.0.0-%d", i%2))
		inputs[i].DatabasePath = valid.DatabasePath
		inputs[i].AllPackages = i%2 == 0
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, req := range inputs {
		wg.Go(func() {
			<-start
			for round := range 4 {
				input := req
				failed := (round+i)%3 == 0
				if failed {
					input.DatabasePath = bad.DatabasePath
				}
				result := execute(input)
				if failed {
					if result.Error == nil || result.Error.Code != "offline_unavailable" || len(result.Result.Results) != 0 {
						t.Errorf("worker %d: missing DB reported as clean: %+v", i, result)
					}
					continue
				}
				if result.Error != nil || len(result.Result.Results) == 0 || len(result.Result.Results[0].Packages) == 0 {
					t.Errorf("worker %d: unsuccessful scan: %+v", i, result.Error)
					return
				}
				pkg := result.Result.Results[0].Packages[0]
				if pkg.Package.Version != fmt.Sprintf("3.0.0-%d", i%2) || len(pkg.Vulnerabilities) != 1 || pkg.Vulnerabilities[0].GetId() != "OSVPY-TEST-0001" {
					t.Errorf("worker %d: mixed scan result", i)
				}
			}
		})
	}
	close(start)
	wg.Wait()
}
