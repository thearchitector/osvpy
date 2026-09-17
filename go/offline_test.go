package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineDatabaseFailures(t *testing.T) {
	for _, kind := range []string{"missing", "unreadable", "invalid", "truncated", "crc"} {
		for _, inventory := range []bool{false, true} {
			t.Run(kind+"/inventory="+map[bool]string{true: "true", false: "false"}[inventory], func(t *testing.T) {
				req := offlineRequest(t, "3.0.0-1")
				req.AllPackages = inventory
				path := filepath.Join(req.DatabasePath, "osv-scalibr", "Ubuntu", "all.zip")
				var err error
				switch kind {
				case "missing":
					err = os.Remove(path)
				case "unreadable":
					err = os.Chmod(path, 0)
					t.Cleanup(func() { _ = os.Chmod(path, 0600) })
					if f, openErr := os.Open(path); openErr == nil {
						f.Close()
						t.Skip("this user bypasses file permissions")
					}
				case "invalid":
					err = os.WriteFile(path, []byte("not a ZIP"), 0600)
				case "truncated":
					err = os.Truncate(path, 40)
				case "crc":
					var buf bytes.Buffer
					zw := zip.NewWriter(&buf)
					w, createErr := zw.CreateHeader(&zip.FileHeader{Name: "unused.json", Method: zip.Store})
					if createErr != nil {
						t.Fatal(createErr)
					}
					_, _ = w.Write([]byte(`{"id":"UNUSED"}`))
					if closeErr := zw.Close(); closeErr != nil {
						t.Fatal(closeErr)
					}
					data := bytes.Replace(buf.Bytes(), []byte("UNUSED"), []byte("BROKEN"), 1)
					err = os.WriteFile(path, data, 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
				result := execute(req)
				if result.Error == nil || result.Error.Code != "offline_unavailable" || len(result.Result.Results) != 0 {
					t.Fatalf("failed database must discard partial results: %+v", result)
				}
				if result.Metadata.AllPackages != inventory || result.Metadata.ImageDigest == "" {
					t.Fatalf("lost metadata: %+v", result.Metadata)
				}
			})
		}
	}
}
