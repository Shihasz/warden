// Package kev fetches and queries CISA's Known Exploited Vulnerabilities
// catalog — the official, authoritative list of CVEs confirmed to have
// been exploited in the wild.
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// FeedURL is CISA's official, no-auth-required KEV catalog feed.
const FeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// Catalog is CISA's KEV catalog.
type Catalog struct {
	Title           string          `json:"title"`
	CatalogVersion  string          `json:"catalogVersion"`
	DateReleased    string          `json:"dateReleased"`
	Count           int             `json:"count"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`

	cveSet map[string]struct{}
}

// Vulnerability is a single KEV catalog entry.
type Vulnerability struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

// IsKnownExploited reports whether cveID appears in the catalog. The
// lookup set is built lazily on first use rather than at parse time, so
// constructing a Catalog stays a pure JSON-unmarshal with no extra work
// for callers who only want the raw data.
func (c *Catalog) IsKnownExploited(cveID string) bool {
	if c.cveSet == nil {
		c.cveSet = make(map[string]struct{}, len(c.Vulnerabilities))
		for _, v := range c.Vulnerabilities {
			c.cveSet[v.CVEID] = struct{}{}
		}
	}
	_, ok := c.cveSet[cveID]
	return ok
}

// LoadFile reads and parses a KEV catalog JSON file already on disk. Used
// internally to read back a cached copy, and directly via a --kev-file
// flag — so tests and offline/air-gapped runs never need network access.
func LoadFile(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read KEV catalog file: %w", err)
	}
	return parse(data)
}

// parse decodes a KEV catalog and rejects one with no entries. An empty
// catalog would silently mark nothing as known-exploited, weakening the
// gate without any error; the real catalog has well over a thousand
// entries, so zero means we were handed something that isn't the catalog
// (an API error body, a placeholder, and so on).
func parse(data []byte) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse KEV catalog: %w", err)
	}
	if len(c.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("KEV catalog contains no vulnerabilities")
	}
	return &c, nil
}

// Warnf reports a non-fatal problem encountered while loading the
// catalog. A nil Warnf discards warnings.
type Warnf func(format string, args ...any)

func (w Warnf) printf(format string, args ...any) {
	if w != nil {
		w(format, args...)
	}
}

// FetchAndCache returns the KEV catalog, using cachePath as a local cache.
// A cached copy younger than maxAge is used as-is, with no network call.
// Otherwise the catalog is fetched fresh from FeedURL, validated, and
// cached.
//
// The cache is best-effort and never trusted blindly: only data that
// parses as a non-empty catalog is ever written to it, a cache file that
// fails to load is treated as a miss, and a failure to write the cache is
// reported through warnf without discarding the fetched catalog.
func FetchAndCache(ctx context.Context, cachePath string, maxAge time.Duration, warnf Warnf) (*Catalog, error) {
	return fetchAndCache(ctx, FeedURL, cachePath, maxAge, warnf)
}

// fetchAndCache is the testable core of FetchAndCache — it takes the feed
// URL as a parameter so tests can point it at an httptest.Server instead
// of CISA's real endpoint.
func fetchAndCache(ctx context.Context, url, cachePath string, maxAge time.Duration, warnf Warnf) (*Catalog, error) {
	if info, err := os.Stat(cachePath); err == nil && time.Since(info.ModTime()) <= maxAge {
		c, loadErr := LoadFile(cachePath)
		if loadErr == nil {
			return c, nil
		}
		// A fresh-looking cache file that can't be loaded (truncated by a
		// crash mid-write, or garbage cached by an older warden) is a
		// cache miss, not a fatal error.
		warnf.printf("ignoring unusable KEV cache %s: %v", cachePath, loadErr)
	}

	data, c, err := fetchValidated(ctx, url)
	if err == nil {
		if werr := writeCacheAtomic(cachePath, data); werr != nil {
			warnf.printf("could not cache the KEV catalog at %s: %v (continuing without caching)", cachePath, werr)
		}
		return c, nil
	}

	// Refreshing failed. A stale-but-valid cache beats failing the whole
	// gate because CISA's server had a bad moment — but say so, so the
	// staleness is visible rather than silent.
	if stale, loadErr := LoadFile(cachePath); loadErr == nil {
		warnf.printf("could not refresh the KEV catalog (%v); using the cached copy at %s", err, cachePath)
		return stale, nil
	}

	return nil, fmt.Errorf("fetch KEV catalog: %w", err)
}

// fetchValidated downloads the catalog and returns the raw bytes only if
// they parse as a valid, non-empty catalog.
func fetchValidated(ctx context.Context, url string) ([]byte, *Catalog, error) {
	data, err := fetch(ctx, url)
	if err != nil {
		return nil, nil, err
	}
	c, err := parse(data)
	if err != nil {
		return nil, nil, fmt.Errorf("fetched data is not a valid KEV catalog: %w", err)
	}
	return data, c, nil
}

// writeCacheAtomic writes data to path via a temporary file in the same
// directory followed by a rename, so a concurrent reader (or a crash
// mid-write) can never observe a partially written cache file.
func writeCacheAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".kev-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary cache file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		// A harmless no-op after a successful rename, since tmpPath no
		// longer exists by then; cleans up on every failure path.
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary cache file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary cache file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return fmt.Errorf("set cache file permissions: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace cache file: %w", err)
	}
	return nil
}

func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	return io.ReadAll(resp.Body)
}
