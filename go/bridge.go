// Package main implements the normalized reporting boundary.
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

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
	AllowedLicenses []string      `json:"allowed_licenses"`
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
	DatabasePath    string  `json:"database_path"`
}

type response struct {
	Result   models.VulnerabilityResults
	Metadata scanMetadata
	Error    *nativeError
}

func failure(code, message string) response {
	return response{Error: &nativeError{Code: code, Message: message}}
}

func execute(req request) (out response) {
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

	osvscanner.SetLogger(slog.NewTextHandler(io.Discard, nil))
	started := time.Now()
	path := req.Image
	metadata := &scanMetadata{ScannerVersion: scannerVersion, Source: req.Source,
		Offline: req.Offline, AllPackages: req.AllPackages, DatabasePath: req.DatabasePath}
	defer func() {
		metadata.DurationSeconds = time.Since(started).Seconds()
		out.Metadata = *metadata
	}()
	if req.Source == "registry" {
		// Explicit auth only. DefaultKeychain can execute Docker credential helpers.
		auth := authn.Anonymous
		if req.Auth != nil {
			auth = &authn.Basic{Username: req.Auth.Username, Password: req.Auth.Password}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		opts := []remote.Option{remote.WithContext(ctx), remote.WithAuth(auth), remote.WithUserAgent("osvpy/0.1.0")}
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
		dir, err := os.MkdirTemp("", "osvpy-")
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
		// Validate the single-image Docker-save contract and retain available
		// identity before the scanner constructs its inventory graph.
		img, err := tarball.ImageFromPath(path, nil)
		if err != nil {
			return failure("scan_error", err.Error())
		}
		config, err := img.ConfigFile()
		if err != nil {
			return failure("scan_error", err.Error())
		}
		if config.OS != "linux" {
			return failure("unsupported_image", "Only Linux container images are supported")
		}
		digest, err := img.Digest()
		if err != nil {
			return failure("scan_error", err.Error())
		}
		metadata.ImageDigest = digest.String()
		metadata.ImagePlatform = config.OS + "/" + config.Architecture
	}
	actions := osvscanner.ScannerActions{
		Image: path, IsImageArchive: true, ShowAllPackages: req.AllPackages || req.AllowedLicenses != nil,
		CompareOffline: req.Offline, PluginNetworkDisabled: req.Offline,
		LocalDBPath: req.DatabasePath, DownloadDatabases: false,
		ScanLicensesAllowlist: req.AllowedLicenses,
		ScanLicensesSummary:   req.AllowedLicenses != nil,
		RequestUserAgent:      "osvpy/0.1.0",
		TransitiveScanning:    osvscanner.TransitiveScanningActions{Disabled: true},
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
				if len(req.AllowedLicenses) == 0 {
					pkg.LicenseViolations = slices.Clone(pkg.Licenses)
				}
			}
			if !req.AllPackages {
				result.Results[i].Packages = slices.DeleteFunc(result.Results[i].Packages, func(p models.PackageVulns) bool {
					return len(p.Vulnerabilities) == 0 && len(p.LicenseViolations) == 0 && len(p.Licenses) > 0
				})
			}
		}
	}
	return response{Result: result, Metadata: *metadata}
}

func acquisitionError(err error) response {
	if transportError, ok := errors.AsType[*transport.Error](err); ok {
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
