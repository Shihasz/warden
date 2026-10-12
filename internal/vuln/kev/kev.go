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

func parse(data []byte) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse KEV catalog: %w", err)
	}
	return &c, nil
}

// Warnf reports a non-fatal problem encountered while loading the
// catalog. A nil Warnf discards warnings.
type Warnf func(format string, args ...any)

// FetchAndCache returns the KEV catalog, using cachePath as a local cache.
// If cachePath is missing or older than maxAge, it's fetched fresh from
// FeedURL and the cache is overwritten; otherwise the cached copy is used
// as-is, with no network call at all.
//
// The cache is best-effort: if it can't be written (a read-only
// filesystem, for example), the freshly fetched catalog is still returned
// and the problem is reported through warnf.
func FetchAndCache(ctx context.Context, cachePath string, maxAge time.Duration, warnf Warnf) (*Catalog, error) {
	return fetchAndCache(ctx, FeedURL, cachePath, maxAge, warnf)
}

// fetchAndCache is the testable core of FetchAndCache — it takes the feed
// URL as a parameter so tests can point it at an httptest.Server instead
// of CISA's real endpoint.
func fetchAndCache(ctx context.Context, url, cachePath string, maxAge time.Duration, warnf Warnf) (*Catalog, error) {
	info, statErr := os.Stat(cachePath)
	stale := statErr != nil || time.Since(info.ModTime()) > maxAge

	if !stale {
		return LoadFile(cachePath)
	}

	data, err := fetch(ctx, url)
	if err != nil {
		// Fall back to a stale cache rather than failing outright, if one
		// exists — a CI gate shouldn't hard-fail just because CISA's
		// server had a bad moment, when slightly-old data is sitting
		// right there and is still useful.
		if _, statErr := os.Stat(cachePath); statErr == nil {
			return LoadFile(cachePath)
		}
		return nil, fmt.Errorf("fetch KEV catalog: %w", err)
	}

	// The cache is an optimization, so failing to write it must not
	// discard a catalog we already have in hand.
	if err := writeCache(cachePath, data); err != nil && warnf != nil {
		warnf("could not cache the KEV catalog at %s: %v (continuing without caching)", cachePath, err)
	}

	return parse(data)
}

func writeCache(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write cache file: %w", err)
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
