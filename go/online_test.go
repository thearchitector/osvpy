package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	depsdevpb "deps.dev/api/v3"
	scalibrconfig "github.com/google/osv-scalibr/plugin/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type localClients struct {
	client *http.Client
	conn   *grpc.ClientConn
}

func (c localClients) HTTPClient() *http.Client { return c.client }
func (c localClients) GoogleHTTPClient(context.Context, ...string) (*http.Client, error) {
	return c.client, nil
}
func (c localClients) GRPCClientConn(string, ...grpc.DialOption) (grpc.ClientConnInterface, error) {
	return c.conn, nil
}

type fixtureTransport struct {
	target    *url.URL
	transport http.RoundTripper
}

func (f fixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	copy := req.Clone(req.Context())
	copy.URL.Scheme, copy.URL.Host = f.target.Scheme, f.target.Host
	return f.transport.RoundTrip(copy)
}

type licenseService struct {
	depsdevpb.UnimplementedInsightsServer
	t    *testing.T
	name string
}

func (s *licenseService) GetVersion(_ context.Context, req *depsdevpb.GetVersionRequest) (*depsdevpb.Version, error) {
	if req.VersionKey.Name != s.name || req.VersionKey.Version != "1.0" {
		s.t.Errorf("mixed license request: %+v", req.VersionKey)
	}
	return &depsdevpb.Version{VersionKey: req.VersionKey, Licenses: []string{"MIT"}}, nil
}

// Each parallel scan has its own HTTP and gRPC clients and fixtures. Nothing
// replaces http.DefaultClient, default transports, or process loggers.
func TestConcurrentOnlineVulnerabilitiesAndLicenses(t *testing.T) {
	for i := range 8 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			name, id := fmt.Sprintf("example-%d", i), fmt.Sprintf("OSVPY-ONLINE-%d", i)
			image := fixtureImage(t, t.TempDir(), map[string][]byte{
				"etc/os-release": []byte("ID=ubuntu\nVERSION_ID=24.04\n"),
				"usr/lib/python3/site-packages/example-1.0.dist-info/METADATA": []byte("Metadata-Version: 2.1\nName: " + name + "\nVersion: 1.0\n"),
			})
			httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.HasSuffix(r.URL.Path, "/querybatch"):
					var body struct {
						Queries []struct {
							Package struct {
								Name string `json:"name"`
							} `json:"package"`
						} `json:"queries"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					results := make([]any, len(body.Queries))
					for j, query := range body.Queries {
						if query.Package.Name != name {
							t.Errorf("mixed vulnerability request: %s", query.Package.Name)
						}
						results[j] = map[string]any{"vulns": []any{map[string]string{"id": id, "modified": "2026-01-01T00:00:00Z"}}}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
				case strings.HasSuffix(r.URL.Path, "/vulns/"+id):
					_, _ = fmt.Fprintf(w, `{"id":%q,"modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":%q,"ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0"}]}]}]}`, id, name)
				default:
					t.Errorf("unexpected HTTP request: %s", r.URL.Path)
					http.Error(w, "unexpected request", http.StatusNotFound)
				}
			}))
			defer httpServer.Close()
			target, err := url.Parse(httpServer.URL)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			service := &licenseService{t: t, name: name}
			server := grpc.NewServer()
			depsdevpb.RegisterInsightsServer(server, service)
			go func() { _ = server.Serve(listener) }()
			defer server.Stop()
			conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			clients := localClients{client: &http.Client{Transport: fixtureTransport{target, httpServer.Client().Transport}, Timeout: 10 * time.Second}, conn: conn}
			allowed := []string{"MIT"}
			if i%2 != 0 {
				allowed = []string{"Apache-2.0"}
			}
			req := request{Image: image, Source: "docker_archive", AllowedLicenses: allowed, AllPackages: i%3 == 0}
			for range 3 {
				result := executeWithConfig(req, &scalibrconfig.PluginConfig{ClientFactories: clients})
				if result.Error != nil || len(result.Result.Results) != 1 || len(result.Result.Results[0].Packages) != 1 {
					t.Fatalf("online scan failed: %+v", result)
				}
				pkg := result.Result.Results[0].Packages[0]
				if pkg.Package.Name != name || len(pkg.Vulnerabilities) != 1 || pkg.Vulnerabilities[0].GetId() != id {
					t.Fatalf("mixed vulnerability results: %+v", pkg)
				}
				if len(pkg.Licenses) != 1 || pkg.Licenses[0] != "MIT" || len(pkg.LicenseViolations) != i%2 {
					t.Fatalf("mixed license policy: %+v", pkg)
				}
			}
		})
	}
}
