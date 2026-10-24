// Package oidctest mints real RS256-signed GitHub-style OIDC tokens under
// a freshly generated key, and publishes the matching JWKS, for tests.
package oidctest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/Shihasz/warden/internal/provenance/oidc"
)

// Signer stands in for GitHub's token-signing key.
type Signer struct {
	kid string
	key *rsa.PrivateKey
}

// NewSigner generates a fresh RSA key published under kid. Two Signers
// with the same kid but different keys model an attacker forging tokens.
func NewSigner(t testing.TB, kid string) *Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return &Signer{kid: kid, key: key}
}

// JWKSJSON returns the signer's public key as a JWKS document.
func (s *Signer) JWKSJSON(t testing.TB) []byte {
	t.Helper()
	doc := map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": s.kid,
		"n":   base64.RawURLEncoding.EncodeToString(s.key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.key.E)).Bytes()),
	}}}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	return data
}

// JWKS returns the signer's public key as a parsed key set.
func (s *Signer) JWKS(t testing.TB) *oidc.JWKS {
	t.Helper()
	jwks, err := oidc.ParseJWKS(s.JWKSJSON(t))
	if err != nil {
		t.Fatalf("parse JWKS: %v", err)
	}
	return jwks
}

// Sign mints an RS256 JWT carrying claims.
func (s *Signer) Sign(t testing.TB, claims oidc.Claims) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": s.kid})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}
