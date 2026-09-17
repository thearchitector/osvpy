package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func TestRegistryOverlapAndIsolation(t *testing.T) {
	arrivals := make(chan struct{}, 2)
	release := make(chan struct{})
	// Release handlers before server cleanup even when an assertion fails.
	releaseScans := sync.OnceFunc(func() { close(release) })
	defer releaseScans()
	inputs := make([]request, 2)
	for i, arch := range []string{"amd64", "arm64"} {
		credential := &registryAuth{Username: "user-" + arch, Password: "password-" + arch}
		handler := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
		var active atomic.Bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()
			if !ok || user != credential.Username || pass != credential.Password {
				w.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if active.Load() && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/manifests/latest") {
				arrivals <- struct{}{}
				select {
				case <-release:
				case <-time.After(10 * time.Second):
					http.Error(w, "scan calls did not overlap", http.StatusGatewayTimeout)
					return
				}
			}
			handler.ServeHTTP(w, r)
		}))
		t.Cleanup(server.Close)
		ref, err := name.ParseReference(strings.TrimPrefix(server.URL, "http://") + "/fixture:latest")
		if err != nil {
			t.Fatal(err)
		}
		path := fixtureImage(t, t.TempDir(), map[string][]byte{"etc/os-release": []byte("ID=ubuntu\nVERSION_ID=24.04\n")})
		img, err := tarball.ImageFromPath(path, nil)
		if err != nil {
			t.Fatal(err)
		}
		index := v1.ImageIndex(empty.Index)
		for _, platform := range []string{"amd64", "arm64"} {
			config, err := img.ConfigFile()
			if err != nil {
				t.Fatal(err)
			}
			config.Architecture = platform
			variant, err := mutate.ConfigFile(img, config)
			if err != nil {
				t.Fatal(err)
			}
			index = mutate.AppendManifests(index, mutate.IndexAddendum{Add: variant, Platform: &v1.Platform{OS: "linux", Architecture: platform}})
		}
		if err := remote.WriteIndex(ref, index, remote.WithAuth(&authn.Basic{Username: credential.Username, Password: credential.Password})); err != nil {
			t.Fatal(err)
		}
		inputs[i] = request{Image: ref.Name(), Source: "registry", Auth: credential, Platform: "linux/" + arch}
		active.Store(true)
	}
	results := make(chan response, 2)
	for _, input := range inputs {
		go func() { results <- execute(input) }()
	}
	for range 2 {
		select {
		case <-arrivals:
		case <-time.After(15 * time.Second):
			t.Fatal("independent acquisitions did not overlap")
		}
	}
	releaseScans()
	platforms := make(map[string]bool)
	for range 2 {
		select {
		case result := <-results:
			if result.Error != nil {
				t.Fatalf("registry scan failed: %+v", result.Error)
			}
			platforms[result.Metadata.ImagePlatform] = true
		case <-time.After(15 * time.Second):
			t.Fatal("registry scan did not finish")
		}
	}
	if !platforms["linux/amd64"] || !platforms["linux/arm64"] {
		t.Fatalf("mixed platform selection: %v", platforms)
	}
}
