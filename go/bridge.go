// Package main implements the versioned JSON/C boundary. No Go pointer escapes it.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"
	"unsafe"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
)

const scannerVersion = "2.6.0"

// Upstream SetLogger replaces process-global mutable state. Serialize scans so
// log routing and upstream logger state cannot bleed between Python callers.
var scanMu sync.Mutex

type registryAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type request struct {
	Image           string        `json:"image"`
	Source          string        `json:"source"`
	Offline         bool          `json:"offline"`
	AllPackages     bool          `json:"all_packages"`
	Auth            *registryAuth `json:"auth,omitempty"`
	Platform        string        `json:"platform,omitempty"`
	DatabasePath    string        `json:"database_path,omitempty"`
	Detail          string        `json:"detail,omitempty"`
	AllowedLicenses []string      `json:"allowed_licenses,omitempty"`
}

type nativeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type scanMetadata struct {
	ScannerVersion  string  `json:"scanner_version"`
	Source          string  `json:"source"`
	Offline         bool    `json:"offline"`
	AllPackages     bool    `json:"all_packages"`
	ImageDigest     string  `json:"image_digest,omitempty"`
	ImagePlatform   string  `json:"image_platform,omitempty"`
	DurationSeconds float64 `json:"duration_seconds"`
	NoPackages      bool    `json:"no_packages"`
}

type response struct {
	ABIVersion int           `json:"abi_version"`
	OK         bool          `json:"ok"`
	Result     *fullScanData `json:"result,omitempty"`
	Report     *scanResult   `json:"report,omitempty"`
	Error      *nativeError  `json:"error,omitempty"`
}

func failure(code, message string) response {
	return response{ABIVersion: 3, Error: &nativeError{Code: code, Message: message}}
}

// invoke also recovers panics when exercised from Go tests. Panic values are
// intentionally not returned: dependencies may include credentials in errors.
func invoke(data []byte) (out []byte) {
	return encodeResponse(func() response { return execute(data) })
}

func encodeResponse(run func() response) (out []byte) {
	defer func() {
		if recover() != nil {
			out = []byte(`{"abi_version":3,"ok":false,"error":{"code":"internal_error","message":"Native scanner panicked"}}`)
		}
	}()
	r := run()
	out, err := json.Marshal(r)
	if err != nil {
		return []byte(`{"abi_version":3,"ok":false,"error":{"code":"internal_error","message":"Cannot serialize scanner response"}}`)
	}
	return out
}

//export osv_scan_image
func osv_scan_image(input *C.char) (out *C.char) {
	return C.CString(string(invoke([]byte(C.GoString(input)))))
}

//export osv_free_string
func osv_free_string(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

func execute(data []byte) response {
	var req request
	if err := json.Unmarshal(data, &req); err != nil {
		return failure("invalid_request", err.Error())
	}
	if req.Source == "" {
		req.Source = "registry"
	}
	if req.Detail != "" && req.Detail != "compact" && req.Detail != "full" {
		return failure("invalid_request", "detail must be compact or full")
	}
	if req.Offline && req.AllowedLicenses != nil {
		return failure("offline_unavailable", "License checks require online scanning")
	}
	if req.Offline && req.Source == "registry" {
		return failure("offline_unavailable", "Offline scans require a local Docker archive and a pre-populated database_path")
	}
	if req.Offline && req.DatabasePath == "" {
		return failure("offline_unavailable", "Offline scans require a pre-populated database_path")
	}
	var ref name.Reference
	var platform *v1.Platform
	if req.Source == "registry" {
		var err error
		ref, err = name.ParseReference(req.Image)
		if err != nil {
			return failure("invalid_image", err.Error())
		}
		if req.Platform != "" {
			platform, err = v1.ParsePlatform(req.Platform)
			if err != nil {
				return failure("invalid_request", err.Error())
			}
		}
	}

	scanMu.Lock()
	defer scanMu.Unlock()
	osvscanner.SetLogger(slog.NewTextHandler(io.Discard, nil))
	started := time.Now()
	path := req.Image
	metadata := &scanMetadata{ScannerVersion: scannerVersion, Source: req.Source,
		Offline: req.Offline, AllPackages: req.AllPackages}
	if req.Source == "registry" {
		// Explicit auth only. DefaultKeychain can execute Docker credential helpers.
		auth := authn.Anonymous
		if req.Auth != nil {
			auth = &authn.Basic{Username: req.Auth.Username, Password: req.Auth.Password}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		opts := []remote.Option{remote.WithContext(ctx), remote.WithAuth(auth), remote.WithUserAgent("pyosv/0.1.0")}
		if platform != nil {
			opts = append(opts, remote.WithPlatform(*platform))
		}
		img, err := remote.Image(ref, opts...)
		if err != nil {
			return acquisitionError(err)
		}
		config, err := img.ConfigFile()
		if err != nil {
			return acquisitionError(err)
		}
		if config.OS != "linux" {
			return failure("unsupported_image", "Only Linux container images are supported")
		}
		digest, err := img.Digest()
		if err != nil {
			return acquisitionError(err)
		}
		metadata.ImageDigest = digest.String()
		metadata.ImagePlatform = config.OS + "/" + config.Architecture
		dir, err := os.MkdirTemp("", "pyosv-")
		if err != nil {
			return failure("scan_error", err.Error())
		}
		defer os.RemoveAll(dir)
		path = dir + "/image.tar"
		if err := tarball.WriteToFile(path, ref, img); err != nil {
			return acquisitionError(err)
		}
	} else {
		_, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			return failure("image_not_found", "Image archive does not exist")
		}
		if err != nil {
			return failure("scan_error", err.Error())
		}
	}
	actions := osvscanner.ScannerActions{
		Image: path, IsImageArchive: true, ShowAllPackages: req.AllPackages || req.AllowedLicenses != nil,
		CompareOffline: req.Offline, PluginNetworkDisabled: req.Offline,
		LocalDBPath: req.DatabasePath, DownloadDatabases: false,
		ScanLicensesAllowlist: req.AllowedLicenses,
		ScanLicensesSummary:   req.AllowedLicenses != nil,
		ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
			RequestUserAgent:   "pyosv/0.1.0",
			TransitiveScanning: osvscanner.TransitiveScanningActions{Disabled: true},
		},
	}
	result, err := osvscanner.DoContainerScan(actions)
	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) && !errors.Is(err, osvscanner.ErrNoPackagesFound) {
		if req.Offline {
			return failure("offline_unavailable", err.Error())
		}
		return failure("scan_error", err.Error())
	}
	metadata.DurationSeconds = time.Since(started).Seconds()
	metadata.NoPackages = errors.Is(err, osvscanner.ErrNoPackagesFound)
	if req.AllowedLicenses != nil {
		// Plugin failures can be nonfatal upstream. Never turn a skipped license
		// lookup into a successful empty compliance report.
		for i := range result.Results {
			for j := range result.Results[i].Packages {
				pkg := &result.Results[i].Packages[j]
				if len(pkg.Licenses) == 0 {
					return failure("scan_error", "License information could not be retrieved for all detected packages")
				}
				if len(req.AllowedLicenses) == 0 {
					pkg.LicenseViolations = slices.Clone(pkg.Licenses)
				}
			}
			if !req.AllPackages {
				result.Results[i].Packages = slices.DeleteFunc(result.Results[i].Packages, func(p models.PackageVulns) bool {
					return len(p.Vulnerabilities) == 0 && len(p.LicenseViolations) == 0
				})
			}
		}
	}
	resp := response{ABIVersion: 3, OK: true}
	if req.Detail == "full" {
		resp.Result = &fullScanData{VulnerabilityResults: result, Image: req.Image, Metadata: *metadata}
	} else {
		resp.Report = compactResults(result, req, *metadata)
	}
	return resp
}

func acquisitionError(err error) response {
	var transportError *transport.Error
	if errors.As(err, &transportError) {
		switch transportError.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return failure("registry_authentication", "Registry denied access; supply credentials with pull permission")
		case http.StatusNotFound:
			return failure("image_not_found", "Registry image, tag or digest was not found")
		}
	}
	return failure("scan_error", err.Error())
}

func main() {}
