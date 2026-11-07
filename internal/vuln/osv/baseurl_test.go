package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Shihasz/warden/internal/sbom"
)

func TestWithBaseURL_UsesStandardOSVPaths(t *testing.T) {
	var unexpected []string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(batchResponse{Results: []batchResult{{Vulns: []minimalVuln{{ID: "OSV-MOCK-1"}}}}})
	})
	mux.HandleFunc("/v1/vulns/OSV-MOCK-1", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Vulnerability{ID: "OSV-MOCK-1", Aliases: []string{"CVE-2099-0001"}})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		unexpected = append(unexpected, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	// The trailing slash must not produce a double slash in the paths.
	client := NewClient(WithBaseURL(server.URL + "/"))

	findings, _, err := client.Scan(context.Background(), []sbom.Component{
		{Name: "foo", Version: "1.0.0", PURL: "pkg:pypi/foo@1.0.0"},
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(unexpected) != 0 {
		t.Errorf("client requested unexpected paths: %v", unexpected)
	}
	if len(findings) != 1 || len(findings[0].Vulns) != 1 || findings[0].Vulns[0].ID != "OSV-MOCK-1" {
		t.Errorf("findings = %+v, want one finding with OSV-MOCK-1", findings)
	}
}
