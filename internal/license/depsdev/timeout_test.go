package depsdev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Shihasz/warden/internal/sbom"
)

func TestNewClient_DefaultHasTimeout(t *testing.T) {
	if NewClient().httpClient.Timeout <= 0 {
		t.Fatal("default deps.dev client has no timeout — requests to a silent server would hang forever")
	}
}

func TestLookup_HungServerIsSkippedNotHung(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(&http.Client{Timeout: 100 * time.Millisecond}),
		WithBaseURL(server.URL),
	)

	start := time.Now()
	results, skipped, err := client.Lookup(context.Background(), []sbom.Component{
		{Name: "foo", Version: "1.0.0", PURL: "pkg:npm/foo@1.0.0"},
	})
	if err != nil {
		t.Fatalf("Lookup() error = %v, want nil (a failed lookup is recorded as skipped)", err)
	}
	if len(results) != 0 || len(skipped) != 1 {
		t.Fatalf("got %d results and %d skipped, want 0 and 1", len(results), len(skipped))
	}
	if !strings.Contains(skipped[0].Reason, "deps.dev lookup failed") {
		t.Errorf("skip reason = %q, want it to say the lookup failed", skipped[0].Reason)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Lookup() took %v to give up, want it bounded near the 100ms client timeout", elapsed)
	}
}
