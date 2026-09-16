package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func fixtureTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for name, body := range files {
		if err := w.WriteHeader(&tar.Header{Name: name, Size: int64(len(body)), Mode: 0600}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func offlineRequest(t *testing.T, version string) []byte {
	t.Helper()
	dir := t.TempDir()
	layer := fixtureTar(t, map[string][]byte{
		"etc/os-release":      []byte("ID=ubuntu\nVERSION_ID=24.04\n"),
		"var/lib/dpkg/status": []byte(fmt.Sprintf("Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: %s\nDescription: fixture\n\n", version)),
	})
	config := fmt.Sprintf(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:%x"]},"history":[{"created_by":"fixture"}],"config":{}}`, sha256.Sum256(layer))
	archive := fixtureTar(t, map[string][]byte{
		"config.json": []byte(config), "layer.tar": layer,
		"manifest.json": []byte(`[{"Config":"config.json","RepoTags":["fixture:latest"],"Layers":["layer.tar"]}]`),
	})
	path := filepath.Join(dir, "fixture.tar")
	if err := os.WriteFile(path, archive, 0600); err != nil {
		t.Fatal(err)
	}
	dbDir := filepath.Join(dir, "osv-scalibr", "Ubuntu")
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		t.Fatal(err)
	}
	var zipped bytes.Buffer
	zw := zip.NewWriter(&zipped)
	w, err := zw.Create("PYOSV-TEST-0001.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte(`{"id":"PYOSV-TEST-0001","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"openssl","ecosystem":"Ubuntu:24.04"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.0-2"}]}]}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbDir, "all.zip"), zipped.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(request{Image: path, Source: "docker_archive", Offline: true, DatabasePath: dir, Detail: "full"})
	if err != nil {
		t.Fatal(err)
	}
	return input
}

// Exercise concurrent native requests under the Go race detector. Python's
// functional tests cover reporting/options; the standalone stress script covers
// repeated calls and memory growth.
func TestConcurrentScansKeepInstalledVersionsSeparate(t *testing.T) {
	for _, version := range []string{"3.0.0-0", "3.0.0-1"} {
		input := offlineRequest(t, version)
		t.Run(version, func(t *testing.T) {
			t.Parallel()
			var result response
			if err := json.Unmarshal(invoke(input), &result); err != nil {
				t.Fatal(err)
			}
			if !result.OK {
				t.Fatalf("scan failed: %+v", result.Error)
			}
			pkg := result.Result.Results[0].Packages[0]
			if pkg.Package.Version != version {
				t.Fatalf("installed version: got %q, want %q", pkg.Package.Version, version)
			}
			if pkg.Vulnerabilities[0].GetId() != "PYOSV-TEST-0001" {
				t.Fatal("expected fixture vulnerability")
			}
		})
	}
}
