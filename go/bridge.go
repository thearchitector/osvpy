// Package main implements the normalized reporting boundary.
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	scalibrimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	scalibrlog "github.com/google/osv-scalibr/log"
	scalibrconfig "github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
)

const scannerVersion = "2.6.0"

// The bundled Go runtime owns logging configuration for its lifetime. Do not
// install osvscanner.SetLogger: its wrapper mutates error state during scans.
var loggerOnce sync.Once

type registryAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type request struct {
	Inputs          []string      `json:"inputs"`
	Workers         int           `json:"workers"`
	Languages       []string      `json:"languages"`
	Image           string        `json:"image"`
	AllPackages     bool          `json:"all_packages"`
	Auth            *registryAuth `json:"auth,omitempty"`
	Platform        string        `json:"platform,omitempty"`
	AllowedLicenses []string      `json:"allowed_licenses"`
}

type scanMetadata struct {
	Languages       []string `json:"languages,omitempty"`
	ScannerVersion  string   `json:"scanner_version"`
	AllPackages     bool     `json:"all_packages"`
	ImageDigest     string   `json:"image_digest,omitempty"`
	ImagePlatform   string   `json:"image_platform,omitempty"`
	DurationSeconds float64  `json:"duration_seconds"`
	NoPackages      bool     `json:"no_packages"`
}

type nativeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type response struct {
	Result   models.VulnerabilityResults
	Metadata scanMetadata
	Error    *nativeError
}

func failure(code, message string) response {
	return response{Error: &nativeError{Code: code, Message: message}}
}

func execute(req request) response {
	return executeWithConfig(req, nil)
}

// Per-call dependencies allow hermetic network tests without replacing global
// HTTP clients or loggers while other scans are running.
func executeWithConfig(req request, config *scalibrconfig.PluginConfig) response {
	return executeContext(context.Background(), req, config)
}

func executeContext(ctx context.Context, req request, config *scalibrconfig.PluginConfig) (out response) {
	if req.Languages == nil {
		req.Languages = defaultLanguages()
	}
	checkContext(ctx)
	ref, err := name.ParseReference(req.Image)
	if err != nil {
		return failure("invalid_image", err.Error())
	}
	var platform *v1.Platform
	if req.Platform != "" {
		platform, err = v1.ParsePlatform(req.Platform)
		if err != nil {
			return failure("invalid_request", err.Error())
		}
	}
	loggerOnce.Do(func() {
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
		scalibrlog.SetLogger(discardLogger{})
	})
	started := time.Now()
	metadata := scanMetadata{ScannerVersion: scannerVersion, AllPackages: req.AllPackages, Languages: req.Languages}
	defer func() {
		metadata.DurationSeconds = time.Since(started).Seconds()
		out.Metadata = metadata
	}()
	// Explicit auth only. DefaultKeychain can execute Docker credential helpers.
	auth := authn.Anonymous
	if req.Auth != nil {
		auth = &authn.Basic{Username: req.Auth.Username, Password: req.Auth.Password}
	}
	opts := []remote.Option{remote.WithContext(ctx), remote.WithAuth(auth), remote.WithUserAgent("osvpy/0.1.0")}
	if platform != nil {
		opts = append(opts, remote.WithPlatform(*platform))
	}
	img, err := remote.Image(ref, opts...)
	if err != nil {
		return acquisitionError(err)
	}
	imageConfig, err := img.ConfigFile()
	if err != nil {
		return acquisitionError(err)
	}
	if imageConfig.OS != "linux" {
		return failure("unsupported_image", "Only Linux container images are supported")
	}
	digest, err := img.Digest()
	if err != nil {
		return acquisitionError(err)
	}
	metadata.ImageDigest = digest.String()
	metadata.ImagePlatform = imageConfig.OS + "/" + imageConfig.Architecture
	prepared, err := scalibrimage.FromV1ImageContext(ctx, img, scalibrimage.DefaultConfig())
	if err != nil {
		return failure("scan_error", err.Error())
	}
	defer prepared.CleanUp()
	disabled := []string{"baseimage"}
	for _, plugin := range defaultLanguages() {
		if !slices.Contains(req.Languages, plugin) {
			disabled = append(disabled, plugin)
		}
	}
	actions := osvscanner.ScannerActions{
		PluginsEnabled: slices.Clone(req.Languages), PluginsDisabled: disabled,
		Image: req.Image, ShowAllPackages: req.AllPackages || req.AllowedLicenses != nil,
		ScanLicensesAllowlist: req.AllowedLicenses,
		ScanLicensesSummary:   req.AllowedLicenses != nil,
		RequestUserAgent:      "osvpy/0.1.0",
		TransitiveScanning:    osvscanner.TransitiveScanningActions{Disabled: true},
		ScalibrConfig:         config,
	}
	result, err := osvscanner.DoPreparedContainerScan(ctx, actions, prepared)
	checkContext(ctx)
	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) && !errors.Is(err, osvscanner.ErrNoPackagesFound) {
		return failure("scan_error", err.Error())
	}
	metadata.NoPackages = errors.Is(err, osvscanner.ErrNoPackagesFound)
	if req.AllowedLicenses != nil {
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
	return response{Result: result}
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

func defaultLanguages() []string {
	return []string{"python/wheelegg", "java/archive", "go/binary", "javascript/nodemodules", "rust/cargoauditable"}
}
