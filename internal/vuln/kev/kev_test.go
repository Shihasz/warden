package kev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const fixtureJSON = `{
  "title": "test catalog",
  "catalogVersion": "1.0",
  "dateReleased": "2026-01-01T00:00:00Z",
  "count": 1,
  "vulnerabilities": [
    {
      "cveID": "CVE-2024-00001",
      "vendorProject": "Example",
      "product": "Widget",
      "vulnerabilityName": "Example RCE",
      "dateAdded": "2026-01-01",
      "shortDescription": "test",
      "requiredAction": "patch",
      "dueDate": "2026-02-01",
      "knownRansomwareCampaignUse": "Unknown"
    }
  ]
}`

func TestCatalog_IsKnownExploited(t *testing.T) {
	c, err := parse([]byte(fixtureJSON))
	if err != nil {
		t.Fatalf("parse() error = %v", err)
	}

	if !c.IsKnownExploited("CVE-2024-00001") {
		t.Error("IsKnownExploited(CVE-2024-00001) = false, want true")
	}
	if c.IsKnownExploited("CVE-9999-99999") {
		t.Error("IsKnownExploited(CVE-9999-99999) = true, want false (not in catalog)")
	}
}

func newFixtureServer(hits *int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fixtureJSON))
	}))
}

func TestFetchAndCache_FetchesWhenMissing(t *testing.T) {
	var hits int
	server := newFixtureServer(&hits)
	defer server.Close()

	cachePath := filepath.Join(t.TempDir(), "kev.json")

	c, err := fetchAndCache(context.Background(), server.URL, cachePath, time.Hour)
	if err != nil {
		t.Fatalf("fetchAndCache() error = %v", err)
	}
	if hits != 1 {
		t.Errorf("server hit %d times, want 1", hits)
	}
	if !c.IsKnownExploited("CVE-2024-00001") {
		t.Error("catalog missing expected CVE after fresh fetch")
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Errorf("cache file was not written: %v", err)
	}
}

func TestFetchAndCache_UsesCacheWhenFresh(t *testing.T) {
	var hits int
	server := newFixtureServer(&hits)
	defer server.Close()

	cachePath := filepath.Join(t.TempDir(), "kev.json")
	ctx := context.Background()

	if _, err := fetchAndCache(ctx, server.URL, cachePath, time.Hour); err != nil {
		t.Fatalf("first fetchAndCache() error = %v", err)
	}
	if _, err := fetchAndCache(ctx, server.URL, cachePath, time.Hour); err != nil {
		t.Fatalf("second fetchAndCache() error = %v", err)
	}

	if hits != 1 {
		t.Errorf("server hit %d times, want 1 (second call should have used the cache)", hits)
	}
}

func TestFetchAndCache_RefetchesWhenStale(t *testing.T) {
	var hits int
	server := newFixtureServer(&hits)
	defer server.Close()

	cachePath := filepath.Join(t.TempDir(), "kev.json")
	ctx := context.Background()

	if _, err := fetchAndCache(ctx, server.URL, cachePath, time.Hour); err != nil {
		t.Fatalf("first fetchAndCache() error = %v", err)
	}

	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(cachePath, old, old); err != nil {
		t.Fatalf("Chtimes() error = %v", err)
	}

	if _, err := fetchAndCache(ctx, server.URL, cachePath, time.Hour); err != nil {
		t.Fatalf("second fetchAndCache() error = %v", err)
	}

	if hits != 2 {
		t.Errorf("server hit %d times, want 2 (stale cache should trigger a refetch)", hits)
	}
}

func TestFetchAndCache_FallsBackToStaleCacheOnFetchError(t *testing.T) {
	var hits int
	server := newFixtureServer(&hits)

	cachePath := filepath.Join(t.TempDir(), "kev.json")
	ctx := context.Background()

	if _, err := fetchAndCache(ctx, server.URL, cachePath, time.Hour); err != nil {
		t.Fatalf("first fetchAndCache() error = %v", err)
	}
	server.Close() // further requests to server.URL will now fail

	c, err := fetchAndCache(ctx, server.URL, cachePath, 0) // maxAge 0 forces "stale"
	if err != nil {
		t.Fatalf("fetchAndCache() with a dead server should fall back to the stale cache, got error = %v", err)
	}
	if !c.IsKnownExploited("CVE-2024-00001") {
		t.Error("fallback catalog missing expected CVE")
	}
}
