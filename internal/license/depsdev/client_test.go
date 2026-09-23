package depsdev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Shihasz/warden/internal/sbom"
)

func TestEscapeName(t *testing.T) {
	cases := map[string]string{
		"@scope/name":         "%40scope%2Fname",
		"github.com/acme/lib": "github.com%2Facme%2Flib",
		"requests":            "requests",
	}
	for in, want := range cases {
		if got := escapeName(in); got != want {
			t.Errorf("escapeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSystemAndName(t *testing.T) {
	cases := []struct {
		comp       sbom.Component
		wantSystem string
		wantOK     bool
	}{
		{sbom.Component{Name: "github.com/google/uuid", PURL: "pkg:golang/github.com/google/uuid@v1.6.0"}, "go", true},
		{sbom.Component{Name: "@scope/bar", PURL: "pkg:npm/%40scope/bar@0.5.0"}, "npm", true},
		{sbom.Component{Name: "requests", PURL: "pkg:pypi/requests@2.31.0"}, "pypi", true},
		{sbom.Component{Name: "some-gem", PURL: "pkg:gem/some-gem@1.0.0"}, "", false},
	}
	for _, tc := range cases {
		system, _, ok := systemAndName(tc.comp)
		if ok != tc.wantOK {
			t.Errorf("systemAndName(%q) ok = %v, want %v", tc.comp.PURL, ok, tc.wantOK)
			continue
		}
		if ok && system != tc.wantSystem {
			t.Errorf("systemAndName(%q) system = %q, want %q", tc.comp.PURL, system, tc.wantSystem)
		}
	}
}

func TestLookup(t *testing.T) {
	mux := http.NewServeMux()
	var gotPath string

	mux.HandleFunc("/systems/npm/packages/", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{"licenses":["MIT"]}`))
	})
	mux.HandleFunc("/systems/pypi/packages/unknown-lib/versions/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(WithHTTPClient(server.Client()), WithBaseURL(server.URL))

	components := []sbom.Component{
		{Name: "@scope/bar", Version: "0.5.0", PURL: "pkg:npm/%40scope/bar@0.5.0"},
		{Name: "unknown-lib", Version: "1.0.0", PURL: "pkg:pypi/unknown-lib@1.0.0"},
		{Name: "some-gem", Version: "1.0.0", PURL: "pkg:gem/some-gem@1.0.0"},
		{Name: "unversioned", Version: "", PURL: "pkg:npm/unversioned"},
	}

	results, skipped, err := client.Lookup(context.Background(), components)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 (scoped npm + not-found pypi); results: %+v", len(results), results)
	}
	if len(skipped) != 2 {
		t.Fatalf("got %d skipped, want 2 (unsupported gem type + unversioned); skipped: %+v", len(skipped), skipped)
	}

	wantPath := "/systems/npm/packages/%40scope%2Fbar/versions/0.5.0"
	if gotPath != wantPath {
		t.Errorf("server received path %q, want %q (scope/name percent-encoding likely broken)", gotPath, wantPath)
	}

	var scopedResult, unknownResult LicenseResult
	for _, r := range results {
		switch r.Component.Name {
		case "@scope/bar":
			scopedResult = r
		case "unknown-lib":
			unknownResult = r
		}
	}
	if len(scopedResult.Licenses) != 1 || scopedResult.Licenses[0] != "MIT" {
		t.Errorf("@scope/bar licenses = %v, want [MIT]", scopedResult.Licenses)
	}
	if len(unknownResult.Licenses) != 0 {
		t.Errorf("unknown-lib (404) licenses = %v, want empty (not-found treated as unknown, not error)", unknownResult.Licenses)
	}
}
