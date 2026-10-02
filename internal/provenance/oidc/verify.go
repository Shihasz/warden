package oidc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Issuer is GitHub Actions' OIDC token issuer.
const Issuer = "https://token.actions.githubusercontent.com"

// JWKSURL is GitHub Actions' published JSON Web Key Set endpoint.
const JWKSURL = Issuer + "/.well-known/jwks"

// JWKS is a JSON Web Key Set — the set of public keys a token issuer is
// currently signing with.
type JWKS struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"` // RSA modulus, base64url, unpadded
	E   string `json:"e"` // RSA public exponent, base64url, unpadded
}

// FetchJWKS fetches GitHub Actions' current JWKS.
func FetchJWKS(ctx context.Context, httpClient *http.Client) (*JWKS, error) {
	return fetchJWKS(ctx, httpClient, JWKSURL)
}

// fetchJWKS is the testable core of FetchJWKS — it takes the URL as a
// parameter so tests can point it at a local server instead of GitHub's
// real endpoint.
func fetchJWKS(ctx context.Context, httpClient *http.Client, jwksURL string) (*JWKS, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("JWKS endpoint returned status %d: %s", resp.StatusCode, string(data))
	}

	var set JWKS
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	return &set, nil
}

// publicKey finds the key with the given kid and decodes it into an RSA
// public key.
func (j *JWKS) publicKey(kid string) (*rsa.PublicKey, error) {
	for _, k := range j.Keys {
		if k.Kid != kid {
			continue
		}
		if k.Kty != "RSA" {
			return nil, fmt.Errorf("key %s has unsupported key type %q (only RSA is supported)", kid, k.Kty)
		}

		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("decode modulus for key %s: %w", kid, err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("decode exponent for key %s: %w", kid, err)
		}

		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}, nil
	}
	return nil, fmt.Errorf("no key with kid %q found in JWKS", kid)
}

// Claims is the subset of GitHub Actions OIDC token claims warden uses to
// build provenance. See
// https://docs.github.com/en/actions/concepts/security/openid-connect for
// the full claim set GitHub issues.
//
// Audience is parsed as a single string rather than RFC 7519's
// string-or-array form — GitHub Actions always issues a single string
// audience, so handling the array form would be unused generality.
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
	IssuedAt  int64  `json:"iat"`

	Repository           string `json:"repository"`
	RepositoryOwner      string `json:"repository_owner"`
	RepositoryID         string `json:"repository_id"`
	RepositoryVisibility string `json:"repository_visibility"`
	Ref                  string `json:"ref"`
	SHA                  string `json:"sha"`
	Workflow             string `json:"workflow"`
	WorkflowRef          string `json:"workflow_ref"`
	JobWorkflowRef       string `json:"job_workflow_ref"`
	RunID                string `json:"run_id"`
	RunAttempt           string `json:"run_attempt"`
	RunnerEnvironment    string `json:"runner_environment"`
	Actor                string `json:"actor"`
	EventName            string `json:"event_name"`
}

// VerifyOptions constrains what a verified token must satisfy beyond
// having a valid signature.
type VerifyOptions struct {
	// ExpectedAudience, if set, must match the token's aud claim exactly.
	ExpectedAudience string
	// Now is used for expiry/not-before checks; defaults to time.Now if
	// zero. Overridable so tests don't depend on wall-clock time.
	Now time.Time
}

// Verify parses tokenString as a JWT, checks its RS256 signature against
// jwks, and validates its issuer, expiry, not-before, and (if set)
// audience. It returns the token's claims only if every check passes.
func Verify(tokenString string, jwks *JWKS, opts VerifyOptions) (*Claims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT: expected 3 dot-separated parts, got %d", len(parts))
	}
	headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, fmt.Errorf("decode JWT header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parse JWT header: %w", err)
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported JWT signing algorithm %q (only RS256 is supported)", header.Alg)
	}

	pubKey, err := jwks.publicKey(header.Kid)
	if err != nil {
		return nil, fmt.Errorf("find signing key: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("decode JWT signature: %w", err)
	}

	signingInput := headerB64 + "." + payloadB64
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], sig); err != nil {
		return nil, fmt.Errorf("JWT signature verification failed: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("parse JWT claims: %w", err)
	}

	if claims.Issuer != Issuer {
		return nil, fmt.Errorf("unexpected issuer %q, want %q", claims.Issuer, Issuer)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if claims.ExpiresAt != 0 && now.Unix() >= claims.ExpiresAt {
		return nil, fmt.Errorf("token expired at %s", time.Unix(claims.ExpiresAt, 0).UTC())
	}
	if claims.NotBefore != 0 && now.Unix() < claims.NotBefore {
		return nil, fmt.Errorf("token not valid until %s", time.Unix(claims.NotBefore, 0).UTC())
	}

	if opts.ExpectedAudience != "" && claims.Audience != opts.ExpectedAudience {
		return nil, fmt.Errorf("unexpected audience %q, want %q", claims.Audience, opts.ExpectedAudience)
	}

	return &claims, nil
}
