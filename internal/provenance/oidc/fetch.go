// Package oidc fetches and verifies GitHub Actions OIDC ID tokens, used
// to establish a cryptographically verifiable identity for the CI run
// that produced a build artifact — the foundation a provenance
// attestation is signed against.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

// EnvRequestURL and EnvRequestToken are the environment variables the
// Actions runner injects into a job that has been granted the
// 'id-token: write' permission.
// See https://docs.github.com/en/actions/reference/security/oidc.
const (
	EnvRequestURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	EnvRequestToken = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)

// tokenResponse is the JSON body GitHub's OIDC token endpoint returns.
type tokenResponse struct {
	Value string `json:"value"`
}

// FetchToken requests a GitHub Actions OIDC ID token scoped to audience,
// using the endpoint the Actions runner exposes via EnvRequestURL and
// EnvRequestToken. It returns a descriptive error naming the missing
// variable if either isn't set — which happens when the job lacks the
// 'id-token: write' permission, or isn't running in GitHub Actions at all.
func FetchToken(ctx context.Context, httpClient *http.Client, audience string) (string, error) {
	requestURL := os.Getenv(EnvRequestURL)
	if requestURL == "" {
		return "", fmt.Errorf("%s is not set — this job needs 'permissions: id-token: write', or isn't running in GitHub Actions", EnvRequestURL)
	}
	requestToken := os.Getenv(EnvRequestToken)
	if requestToken == "" {
		return "", fmt.Errorf("%s is not set — this job needs 'permissions: id-token: write', or isn't running in GitHub Actions", EnvRequestToken)
	}

	fullURL, err := addAudience(requestURL, audience)
	if err != nil {
		return "", fmt.Errorf("build OIDC token request URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "bearer "+requestToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request OIDC token: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OIDC token endpoint returned status %d: %s", resp.StatusCode, string(data))
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode OIDC token response: %w", err)
	}
	if tr.Value == "" {
		return "", fmt.Errorf("OIDC token endpoint returned an empty token")
	}

	return tr.Value, nil
}

// addAudience adds an "audience" query parameter to requestURL, correctly
// preserving any query parameters requestURL already has (GitHub's real
// endpoint always includes "?api-version=2.0") rather than assuming a
// fixed "?" vs "&" prefix the way naive string concatenation would.
func addAudience(requestURL, audience string) (string, error) {
	u, err := url.Parse(requestURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
