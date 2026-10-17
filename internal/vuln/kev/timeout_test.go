package kev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newHungServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
}

// useShortTimeout swaps the package's HTTP client for one that gives up
// quickly, restoring the original when the test ends.
func useShortTimeout(t *testing.T) {
	t.Helper()
	old := httpClient
	httpClient = &http.Client{Timeout: 100 * time.Millisecond}
	t.Cleanup(func() { httpClient = old })
}

func TestHTTPClient_HasTimeout(t *testing.T) {
	if httpClient.Timeout <= 0 {
		t.Fatal("the KEV HTTP client has no timeout — a silent server would hang every scan")
	}
}

func TestFetchAndCache_HungServerTimesOut(t *testing.T) {
	server := newHungServer()
	defer server.Close()
	useShortTimeout(t)

	start := time.Now()
	_, err := fetchAndCache(context.Background(), server.URL, filepath.Join(t.TempDir(), "kev.json"), time.Hour, nil)
	if err == nil {
		t.Fatal("fetchAndCache() against a server that never responds should return an error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("fetchAndCache() took %v to give up, want it bounded near the 100ms client timeout", elapsed)
	}
}

func TestFetchAndCache_HungServerFallsBackToStaleCache(t *testing.T) {
	server := newHungServer()
	defer server.Close()
	useShortTimeout(t)

	cachePath := filepath.Join(t.TempDir(), "kev.json")
	if err := os.WriteFile(cachePath, []byte(fixtureJSON), 0o644); err != nil {
		t.Fatalf("write cache fixture: %v", err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(cachePath, old, old); err != nil {
		t.Fatalf("Chtimes() error = %v", err)
	}

	warnf, warnings := collectWarnings()
	c, err := fetchAndCache(context.Background(), server.URL, cachePath, time.Hour, warnf)
	if err != nil {
		t.Fatalf("fetchAndCache() error = %v, want a fallback to the stale cache", err)
	}
	if !c.IsKnownExploited("CVE-2024-00001") {
		t.Error("fallback catalog missing expected CVE")
	}
	if len(*warnings) != 1 || !strings.Contains((*warnings)[0], "could not refresh") {
		t.Errorf("warnings = %v, want one saying the refresh failed", *warnings)
	}
}
