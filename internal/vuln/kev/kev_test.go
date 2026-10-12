package kev

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

	c, err := fetchAndCache(context.Background(), server.URL, cachePath, time.Hour, nil)
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

	if _, err := fetchAndCache(ctx, server.URL, cachePath, time.Hour, nil); err != nil {
		t.Fatalf("first fetchAndCache() error = %v", err)
	}
	if _, err := fetchAndCache(ctx, server.URL, cachePath, time.Hour, nil); err != nil {
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

	if _, err := fetchAndCache(ctx, server.URL, cachePath, time.Hour, nil); err != nil {
		t.Fatalf("first fetchAndCache() error = %v", err)
	}

	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(cachePath, old, old); err != nil {
		t.Fatalf("Chtimes() error = %v", err)
	}

	if _, err := fetchAndCache(ctx, server.URL, cachePath, time.Hour, nil); err != nil {
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

	if _, err := fetchAndCache(ctx, server.URL, cachePath, time.Hour, nil); err != nil {
		t.Fatalf("first fetchAndCache() error = %v", err)
	}
	server.Close() // further requests to server.URL will now fail

	c, err := fetchAndCache(ctx, server.URL, cachePath, 0, nil) // maxAge 0 forces "stale"
	if err != nil {
		t.Fatalf("fetchAndCache() with a dead server should fall back to the stale cache, got error = %v", err)
	}
	if !c.IsKnownExploited("CVE-2024-00001") {
		t.Error("fallback catalog missing expected CVE")
	}
}

// A cache path *inside a regular file* can never be created, for any user
// on any OS, so this fails the same way everywhere. A chmod-based test
// wouldn't: it behaves differently when the tests run as root.
func unwritableCachePath(t *testing.T) string {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	return filepath.Join(blocker, "kev.json")
}

func TestFetchAndCache_UnwritableCacheIsNonFatal(t *testing.T) {
	var hits int
	server := newFixtureServer(&hits)
	defer server.Close()

	cachePath := unwritableCachePath(t)

	var warnings []string
	warnf := func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	}

	c, err := fetchAndCache(context.Background(), server.URL, cachePath, time.Hour, warnf)
	if err != nil {
		t.Fatalf("fetchAndCache() error = %v, want nil (an unwritable cache must not fail the fetch)", err)
	}
	if !c.IsKnownExploited("CVE-2024-00001") {
		t.Error("catalog missing expected CVE — the fetched data was discarded along with the failed cache write")
	}
	if len(warnings) != 1 {
		t.Fatalf("got %d warnings, want exactly 1: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], cachePath) {
		t.Errorf("warning %q should name the cache path %q", warnings[0], cachePath)
	}
}

func TestFetchAndCache_UnwritableCacheWithNilWarnfDoesNotPanic(t *testing.T) {
	var hits int
	server := newFixtureServer(&hits)
	defer server.Close()

	c, err := fetchAndCache(context.Background(), server.URL, unwritableCachePath(t), time.Hour, nil)
	if err != nil {
		t.Fatalf("fetchAndCache() error = %v, want nil", err)
	}
	if !c.IsKnownExploited("CVE-2024-00001") {
		t.Error("catalog missing expected CVE")
	}
}

func newBodyServer(body string, hits *int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
		_, _ = w.Write([]byte(body))
	}))
}

func collectWarnings() (Warnf, *[]string) {
	var warnings []string
	return func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	}, &warnings
}

func TestParse_RejectsEmptyCatalog(t *testing.T) {
	for _, body := range []string{`{}`, `{"vulnerabilities":[]}`, `{"error":"rate limited"}`} {
		if _, err := parse([]byte(body)); err == nil {
			t.Errorf("parse(%s) should reject a catalog with no entries (it would silently mark nothing as exploited), got nil error", body)
		}
	}
}

func TestFetchAndCache_DoesNotCacheInvalidResponse(t *testing.T) {
	for name, body := range map[string]string{
		"html error page": "<html>rate limited</html>",
		"empty catalog":   `{"vulnerabilities":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			var hits int
			server := newBodyServer(body, &hits)
			defer server.Close()

			cachePath := filepath.Join(t.TempDir(), "kev.json")

			if _, err := fetchAndCache(context.Background(), server.URL, cachePath, time.Hour, nil); err == nil {
				t.Fatal("fetchAndCache() with an invalid response and no cache should return an error, got nil")
			}
			if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
				t.Errorf("invalid response was written to the cache (stat error = %v)", err)
			}
		})
	}
}

func TestFetchAndCache_InvalidResponseKeepsGoodCache(t *testing.T) {
	var goodHits int
	good := newFixtureServer(&goodHits)
	defer good.Close()

	cachePath := filepath.Join(t.TempDir(), "kev.json")
	ctx := context.Background()

	if _, err := fetchAndCache(ctx, good.URL, cachePath, time.Hour, nil); err != nil {
		t.Fatalf("seeding the cache: %v", err)
	}
	before, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read seeded cache: %v", err)
	}

	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(cachePath, old, old); err != nil {
		t.Fatalf("Chtimes() error = %v", err)
	}

	var badHits int
	bad := newBodyServer("<html>rate limited</html>", &badHits)
	defer bad.Close()

	warnf, warnings := collectWarnings()
	c, err := fetchAndCache(ctx, bad.URL, cachePath, time.Hour, warnf)
	if err != nil {
		t.Fatalf("fetchAndCache() error = %v, want a fallback to the stale cache", err)
	}
	if !c.IsKnownExploited("CVE-2024-00001") {
		t.Error("fallback catalog missing expected CVE")
	}

	after, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the good cache was overwritten by an invalid response")
	}
	if len(*warnings) != 1 {
		t.Errorf("got %d warnings, want 1 (the stale fallback should be visible): %v", len(*warnings), *warnings)
	}
}

func TestFetchAndCache_CorruptFreshCacheIsRefetched(t *testing.T) {
	var hits int
	server := newFixtureServer(&hits)
	defer server.Close()

	cachePath := filepath.Join(t.TempDir(), "kev.json")
	// Written just now, so its mtime says "fresh" — this is what a crash
	// mid-write (or garbage cached by an older warden) leaves behind.
	if err := os.WriteFile(cachePath, []byte(`{"title": "trunc`), 0o644); err != nil {
		t.Fatalf("write corrupt cache: %v", err)
	}

	warnf, warnings := collectWarnings()
	c, err := fetchAndCache(context.Background(), server.URL, cachePath, time.Hour, warnf)
	if err != nil {
		t.Fatalf("fetchAndCache() error = %v, want it to recover by refetching", err)
	}
	if hits != 1 {
		t.Errorf("server hit %d times, want 1 (a corrupt cache must be treated as a miss)", hits)
	}
	if !c.IsKnownExploited("CVE-2024-00001") {
		t.Error("catalog missing expected CVE after recovery")
	}
	if _, err := LoadFile(cachePath); err != nil {
		t.Errorf("the corrupt cache was not repaired: %v", err)
	}
	if len(*warnings) != 1 {
		t.Errorf("got %d warnings, want 1: %v", len(*warnings), *warnings)
	}
}

func TestFetchAndCache_LeavesNoTempFiles(t *testing.T) {
	var hits int
	server := newFixtureServer(&hits)
	defer server.Close()

	dir := t.TempDir()
	cachePath := filepath.Join(dir, "kev.json")

	if _, err := fetchAndCache(context.Background(), server.URL, cachePath, time.Hour, nil); err != nil {
		t.Fatalf("fetchAndCache() error = %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "kev.json" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("cache directory contains %v, want only kev.json (a temp file was left behind)", names)
	}
}
