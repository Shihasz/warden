package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Shihasz/warden/internal/sbom"
)

func TestScan_SkipsUnversionedAndFindsVulnerable(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		resp := batchResponse{Results: make([]batchResult, len(req.Queries))}
		for i, q := range req.Queries {
			if q.Package.PURL == "pkg:pypi/vulnerable-pkg@1.0.0" {
				resp.Results[i] = batchResult{Vulns: []minimalVuln{{ID: "OSV-2024-0001"}}}
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/vulns/OSV-2024-0001", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Vulnerability{
			ID:      "OSV-2024-0001",
			Summary: "test vulnerability",
			Aliases: []string{"CVE-2024-00001"},
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := &Client{
		httpClient:    server.Client(),
		queryBatchURL: server.URL + "/querybatch",
		vulnBaseURL:   server.URL + "/vulns/",
	}

	components := []sbom.Component{
		{Name: "vulnerable-pkg", Version: "1.0.0", PURL: "pkg:pypi/vulnerable-pkg@1.0.0"},
		{Name: "safe-pkg", Version: "2.0.0", PURL: "pkg:pypi/safe-pkg@2.0.0"},
		{Name: "unpinned-pkg", Version: "", PURL: "pkg:pypi/unpinned-pkg"},
	}

	findings, skipped, err := client.Scan(context.Background(), components)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if len(skipped) != 1 || skipped[0].Component.Name != "unpinned-pkg" {
		t.Fatalf("skipped = %+v, want exactly unpinned-pkg", skipped)
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (safe-pkg should have no vulns)", len(findings))
	}
	f := findings[0]
	if f.Component.Name != "vulnerable-pkg" {
		t.Errorf("finding component = %q, want vulnerable-pkg", f.Component.Name)
	}
	if len(f.Vulns) != 1 || f.Vulns[0].ID != "OSV-2024-0001" {
		t.Fatalf("finding vulns = %+v, want one OSV-2024-0001", f.Vulns)
	}
	if len(f.Vulns[0].Aliases) != 1 || f.Vulns[0].Aliases[0] != "CVE-2024-00001" {
		t.Errorf("vuln aliases = %v, want [CVE-2024-00001]", f.Vulns[0].Aliases)
	}
}

func TestScan_FollowsPagination(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(req.Queries) != 1 {
			t.Fatalf("expected exactly 1 query in this request, got %d", len(req.Queries))
		}

		q := req.Queries[0]
		var result batchResult
		switch q.PageToken {
		case "":
			result = batchResult{Vulns: []minimalVuln{{ID: "OSV-PAGE-1"}}, NextPageToken: "tok1"}
		case "tok1":
			result = batchResult{Vulns: []minimalVuln{{ID: "OSV-PAGE-2"}}}
		default:
			t.Fatalf("unexpected page token %q", q.PageToken)
		}

		_ = json.NewEncoder(w).Encode(batchResponse{Results: []batchResult{result}})
	})

	for _, id := range []string{"OSV-PAGE-1", "OSV-PAGE-2"} {
		id := id
		mux.HandleFunc("/vulns/"+id, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(Vulnerability{ID: id})
		})
	}

	server := httptest.NewServer(mux)
	defer server.Close()

	client := &Client{
		httpClient:    server.Client(),
		queryBatchURL: server.URL + "/querybatch",
		vulnBaseURL:   server.URL + "/vulns/",
	}

	components := []sbom.Component{
		{Name: "many-vulns-pkg", Version: "1.0.0", PURL: "pkg:pypi/many-vulns-pkg@1.0.0"},
	}

	findings, _, err := client.Scan(context.Background(), components)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	gotIDs := map[string]bool{}
	for _, v := range findings[0].Vulns {
		gotIDs[v.ID] = true
	}
	if !gotIDs["OSV-PAGE-1"] || !gotIDs["OSV-PAGE-2"] {
		t.Errorf("findings vulns = %+v, want both OSV-PAGE-1 and OSV-PAGE-2 (pagination should have merged both pages)", findings[0].Vulns)
	}
}
