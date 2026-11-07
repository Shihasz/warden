package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shihasz/warden/internal/endpoints"
	"github.com/Shihasz/warden/internal/vuln/kev"
)

func clearEndpointEnv(t *testing.T) {
	t.Helper()
	for _, env := range []string{endpoints.EnvOSV, endpoints.EnvDepsDev, endpoints.EnvKEV} {
		t.Setenv(env, "")
	}
}

func TestNewDataSources_Defaults(t *testing.T) {
	clearEndpointEnv(t)
	cmd, stderr := newStderrCmd()

	ds, err := newDataSources(cmd)
	if err != nil {
		t.Fatalf("newDataSources() error = %v", err)
	}
	if ds.kevFeed != kev.FeedURL {
		t.Errorf("kevFeed = %q, want the default %q", ds.kevFeed, kev.FeedURL)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want no output when nothing is overridden", stderr.String())
	}
}

func TestNewDataSources_AnnouncesOverrides(t *testing.T) {
	clearEndpointEnv(t)
	t.Setenv(endpoints.EnvKEV, "http://127.0.0.1:9/kev.json")
	cmd, stderr := newStderrCmd()

	ds, err := newDataSources(cmd)
	if err != nil {
		t.Fatalf("newDataSources() error = %v", err)
	}
	if ds.kevFeed != "http://127.0.0.1:9/kev.json" {
		t.Errorf("kevFeed = %q, want the override", ds.kevFeed)
	}
	if !strings.Contains(stderr.String(), endpoints.EnvKEV) {
		t.Errorf("stderr = %q, want a notice naming %s", stderr.String(), endpoints.EnvKEV)
	}
}

func TestNewDataSources_RejectsUnsafeOverride(t *testing.T) {
	clearEndpointEnv(t)
	t.Setenv(endpoints.EnvOSV, "http://example.com")
	cmd, _ := newStderrCmd()

	_, err := newDataSources(cmd)
	requireErrContains(t, err, endpoints.EnvOSV)
}

func TestKEVCachePath_IsolatedPerFeed(t *testing.T) {
	def := &dataSources{kevFeed: kev.FeedURL}
	if got := def.kevCachePath("/c/kev.json"); got != "/c/kev.json" {
		t.Errorf("default feed cache path = %q, want it unchanged", got)
	}

	mock := &dataSources{kevFeed: "http://127.0.0.1:9/kev.json"}
	got := mock.kevCachePath("/c/kev.json")
	if got == "/c/kev.json" || !strings.HasPrefix(got, "/c/kev.json.") {
		t.Errorf("override feed cache path = %q, want a distinct file derived from the base path", got)
	}
	if got != mock.kevCachePath("/c/kev.json") {
		t.Error("the derived cache path is not stable across calls")
	}
}

func TestScan_UsesOSVEndpointOverride(t *testing.T) {
	clearEndpointEnv(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"MOCK-0001"}]}]}`))
	})
	mux.HandleFunc("/v1/vulns/MOCK-0001", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"MOCK-0001","summary":"mock","aliases":["CVE-2099-0001"]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	t.Setenv(endpoints.EnvOSV, server.URL)

	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	sbom := `{"bomFormat":"CycloneDX","components":[{"type":"library","name":"foo","version":"1.0.0","purl":"pkg:pypi/foo@1.0.0"}]}`
	if err := os.WriteFile(sbomPath, []byte(sbom), 0o644); err != nil {
		t.Fatalf("write SBOM: %v", err)
	}

	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--sbom", sbomPath, "--no-kev"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, stderr = %s", err, stderr.String())
	}

	var out struct {
		Findings []struct {
			Vulnerabilities []struct {
				ID string `json:"id"`
			} `json:"vulnerabilities"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout.String())
	}
	if len(out.Findings) != 1 || len(out.Findings[0].Vulnerabilities) != 1 || out.Findings[0].Vulnerabilities[0].ID != "MOCK-0001" {
		t.Errorf("findings = %+v, want the finding served by the mock OSV", out.Findings)
	}
	if !strings.Contains(stderr.String(), endpoints.EnvOSV) {
		t.Errorf("stderr = %q, want a notice naming %s", stderr.String(), endpoints.EnvOSV)
	}
}
