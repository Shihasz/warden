// Package depsdev provides a client for the deps.dev API
// (https://deps.dev), used to look up license information for SBOM
// components across the ecosystems deps.dev supports.
package depsdev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Shihasz/warden/internal/sbom"
)

const defaultBaseURL = "https://api.deps.dev/v3"

// systemFor maps a component's purl type to deps.dev's REST system
// identifier (lowercase, per deps.dev's documented URL scheme).
var systemFor = map[string]string{
	"golang": "go",
	"npm":    "npm",
	"pypi":   "pypi",
}

// LicenseResult is what deps.dev reported for one component.
type LicenseResult struct {
	Component sbom.Component
	// Licenses holds the SPDX identifiers deps.dev returned. An empty
	// slice means deps.dev has no license data for this version — treat
	// that as "unknown", never as "no license"/public domain.
	Licenses []string
}

// Skipped records a component that couldn't be looked up, and why.
type Skipped struct {
	Component sbom.Component
	Reason    string
}

// Client queries deps.dev.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithHTTPClient overrides the http.Client used for requests.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) { c.httpClient = hc }
}

// WithBaseURL overrides the API base URL — mainly for pointing tests at a
// local test server.
func WithBaseURL(url string) ClientOption {
	return func(c *Client) { c.baseURL = url }
}

// NewClient returns a Client targeting the real deps.dev API by default.
func NewClient(opts ...ClientOption) *Client {
	c := &Client{httpClient: http.DefaultClient, baseURL: defaultBaseURL}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Lookup fetches license information for each component. Components with
// an unsupported/unrecognized purl type, or no resolved version, are
// skipped rather than queried. A failed lookup for one component is
// recorded as Skipped rather than aborting the whole call — one flaky
// response shouldn't block license checking for every other component.
func (c *Client) Lookup(ctx context.Context, components []sbom.Component) ([]LicenseResult, []Skipped, error) {
	var results []LicenseResult
	var skipped []Skipped

	for _, comp := range components {
		system, name, ok := systemAndName(comp)
		if !ok {
			skipped = append(skipped, Skipped{Component: comp, Reason: "unsupported purl type for license lookup"})
			continue
		}
		if comp.Version == "" {
			skipped = append(skipped, Skipped{Component: comp, Reason: "no resolved version to look up"})
			continue
		}

		licenses, err := c.getVersion(ctx, system, name, comp.Version)
		if err != nil {
			skipped = append(skipped, Skipped{Component: comp, Reason: fmt.Sprintf("deps.dev lookup failed: %v", err)})
			continue
		}

		results = append(results, LicenseResult{Component: comp, Licenses: licenses})
	}

	return results, skipped, nil
}

func systemAndName(comp sbom.Component) (system, name string, ok bool) {
	for purlType, sys := range systemFor {
		if strings.HasPrefix(comp.PURL, "pkg:"+purlType+"/") {
			return sys, comp.Name, true
		}
	}
	return "", "", false
}

// escapeName percent-encodes the characters deps.dev's HTTP API requires
// escaped within a package name path segment: "@" (npm scopes) and "/"
// (npm scopes and every Go module path), per deps.dev's own documented
// examples.
func escapeName(name string) string {
	name = strings.ReplaceAll(name, "@", "%40")
	name = strings.ReplaceAll(name, "/", "%2F")
	return name
}

type versionResponse struct {
	Licenses []string `json:"licenses"`
}

func (c *Client) getVersion(ctx context.Context, system, name, version string) ([]string, error) {
	url := fmt.Sprintf("%s/systems/%s/packages/%s/versions/%s", c.baseURL, system, escapeName(name), version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// A 404 here typically means deps.dev simply has no record for this
	// exact version (private, unlisted, or very recently published) —
	// that's "no data", not a request failure, so it's returned as an
	// empty result rather than an error.
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("deps.dev returned status %d: %s", resp.StatusCode, string(data))
	}

	var v versionResponse
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("decode deps.dev response: %w", err)
	}
	return v.Licenses, nil
}
