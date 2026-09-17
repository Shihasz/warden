// Package osv provides a client for the OSV.dev vulnerability database
// (https://osv.dev), used to check SBOM components for known
// vulnerabilities.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Shihasz/warden/internal/sbom"
)

const (
	defaultQueryBatchURL = "https://api.osv.dev/v1/querybatch"
	defaultVulnBaseURL   = "https://api.osv.dev/v1/vulns/"

	// maxQueriesPerBatch caps how many queries go in a single querybatch
	// request. OSV doesn't document a hard limit here, but chunking keeps
	// individual requests small and predictable on large dependency trees.
	maxQueriesPerBatch = 1000
)

// Vulnerability is a hydrated OSV vulnerability record — just the fields
// we actually use, not OSV's full schema.
type Vulnerability struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
	Details string `json:"details"`
	// Aliases includes the CVE ID when one has been assigned — this is
	// what we cross-reference against the CISA KEV catalog.
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

// Finding pairs a scanned component with the vulnerabilities OSV reported
// against it.
type Finding struct {
	Component sbom.Component
	Vulns     []Vulnerability
}

// Skipped records a component that couldn't be queried, and why.
type Skipped struct {
	Component sbom.Component
	Reason    string
}

// Client queries OSV.dev.
type Client struct {
	httpClient    *http.Client
	queryBatchURL string
	vulnBaseURL   string
}

// NewClient returns a Client targeting the real OSV.dev API.
func NewClient() *Client {
	return &Client{
		httpClient:    http.DefaultClient,
		queryBatchURL: defaultQueryBatchURL,
		vulnBaseURL:   defaultVulnBaseURL,
	}
}

type indexedComponent struct {
	idx int
	c   sbom.Component
}

// Scan checks each component's PURL against OSV.dev and returns matching
// vulnerabilities, hydrated with full details. Components with no version
// in their PURL are skipped rather than queried, since OSV has nothing
// specific to check them against.
func (c *Client) Scan(ctx context.Context, components []sbom.Component) ([]Finding, []Skipped, error) {
	var queryable []indexedComponent
	var skipped []Skipped
	for i, comp := range components {
		if comp.PURL == "" || !strings.Contains(comp.PURL, "@") {
			skipped = append(skipped, Skipped{Component: comp, Reason: "no resolved version to query"})
			continue
		}
		queryable = append(queryable, indexedComponent{idx: i, c: comp})
	}

	vulnIDsByComponent := make(map[int][]string)
	uniqueIDs := make(map[string]struct{})

	for start := 0; start < len(queryable); start += maxQueriesPerBatch {
		end := start + maxQueriesPerBatch
		if end > len(queryable) {
			end = len(queryable)
		}
		chunk := queryable[start:end]

		results, err := c.queryBatch(ctx, chunk)
		if err != nil {
			return nil, nil, err
		}

		for i, res := range results {
			comp := chunk[i]
			for _, v := range res.Vulns {
				vulnIDsByComponent[comp.idx] = append(vulnIDsByComponent[comp.idx], v.ID)
				uniqueIDs[v.ID] = struct{}{}
			}
		}
	}

	hydrated := make(map[string]Vulnerability, len(uniqueIDs))
	for id := range uniqueIDs {
		v, err := c.getVuln(ctx, id)
		if err != nil {
			return nil, nil, fmt.Errorf("fetch vulnerability %s: %w", id, err)
		}
		hydrated[id] = v
	}

	var findings []Finding
	for _, q := range queryable {
		ids := vulnIDsByComponent[q.idx]
		if len(ids) == 0 {
			continue
		}
		vulns := make([]Vulnerability, 0, len(ids))
		for _, id := range ids {
			vulns = append(vulns, hydrated[id])
		}
		findings = append(findings, Finding{Component: q.c, Vulns: vulns})
	}

	return findings, skipped, nil
}

type batchQuery struct {
	Package   batchPackage `json:"package"`
	PageToken string       `json:"page_token,omitempty"`
}

type batchPackage struct {
	PURL string `json:"purl"`
}

type batchRequest struct {
	Queries []batchQuery `json:"queries"`
}

type minimalVuln struct {
	ID string `json:"id"`
}

type batchResult struct {
	Vulns         []minimalVuln `json:"vulns"`
	NextPageToken string        `json:"next_page_token,omitempty"`
}

type batchResponse struct {
	Results []batchResult `json:"results"`
}

// queryBatch runs one chunk of components through OSV's querybatch
// endpoint, following per-query pagination until every position in the
// chunk has returned all its pages. Per OSV's documented behavior, only
// the specific queries that returned a next_page_token get resent — not
// the whole chunk — so each pagination round can shrink.
func (c *Client) queryBatch(ctx context.Context, chunk []indexedComponent) ([]batchResult, error) {
	results := make([]batchResult, len(chunk))
	pageTokens := make(map[int]string)

	pending := make([]int, len(chunk))
	for i := range chunk {
		pending[i] = i
	}

	for len(pending) > 0 {
		req := batchRequest{Queries: make([]batchQuery, len(pending))}
		for j, pos := range pending {
			req.Queries[j] = batchQuery{
				Package:   batchPackage{PURL: chunk[pos].c.PURL},
				PageToken: pageTokens[pos],
			}
		}

		resp, err := c.doBatchRequest(ctx, req)
		if err != nil {
			return nil, err
		}
		if len(resp.Results) != len(pending) {
			return nil, fmt.Errorf("OSV returned %d results for %d queries", len(resp.Results), len(pending))
		}

		var nextPending []int
		for j, pos := range pending {
			r := resp.Results[j]
			results[pos].Vulns = append(results[pos].Vulns, r.Vulns...)
			if r.NextPageToken != "" {
				pageTokens[pos] = r.NextPageToken
				nextPending = append(nextPending, pos)
			}
		}
		pending = nextPending
	}

	return results, nil
}

func (c *Client) doBatchRequest(ctx context.Context, req batchRequest) (batchResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return batchResponse{}, fmt.Errorf("marshal OSV batch request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.queryBatchURL, bytes.NewReader(body))
	if err != nil {
		return batchResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return batchResponse{}, fmt.Errorf("OSV querybatch request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return batchResponse{}, fmt.Errorf("OSV querybatch returned status %d: %s", resp.StatusCode, string(data))
	}

	var out batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return batchResponse{}, fmt.Errorf("decode OSV querybatch response: %w", err)
	}
	return out, nil
}

func (c *Client) getVuln(ctx context.Context, id string) (Vulnerability, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.vulnBaseURL+id, nil)
	if err != nil {
		return Vulnerability{}, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Vulnerability{}, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return Vulnerability{}, fmt.Errorf("OSV vuln lookup for %s returned status %d: %s", id, resp.StatusCode, string(data))
	}

	var v Vulnerability
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return Vulnerability{}, fmt.Errorf("decode OSV vulnerability %s: %w", id, err)
	}
	return v, nil
}
