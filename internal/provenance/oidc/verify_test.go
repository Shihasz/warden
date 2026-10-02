package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

// signTestToken builds and signs a real JWT for claims using a freshly
// generated RSA key, returning the token and a matching JWKS.
func signTestToken(t *testing.T, claims Claims, kid string) (token string, jwks *JWKS, priv *rsa.PrivateKey) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	header := map[string]string{"alg": "RS256", "kid": kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + payloadB64

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15() error = %v", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	token = signingInput + "." + sigB64

	jwks = &JWKS{Keys: []jwk{{
		Kty: "RSA",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
	}}}

	return token, jwks, priv
}

func validClaims(now time.Time) Claims {
	return Claims{
		Issuer:      Issuer,
		Subject:     "repo:acme/example:ref:refs/heads/main",
		Audience:    "https://github.com/acme",
		ExpiresAt:   now.Add(time.Hour).Unix(),
		NotBefore:   now.Add(-time.Minute).Unix(),
		IssuedAt:    now.Unix(),
		Repository:  "acme/example",
		Ref:         "refs/heads/main",
		SHA:         "abc123",
		Workflow:    "ci",
		WorkflowRef: "acme/example/.github/workflows/ci.yml@refs/heads/main",
		RunID:       "12345",
	}
}

func TestVerify_ValidToken(t *testing.T) {
	now := time.Now()
	token, jwks, _ := signTestToken(t, validClaims(now), "test-key-1")

	claims, err := Verify(token, jwks, VerifyOptions{ExpectedAudience: "https://github.com/acme", Now: now})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims.Repository != "acme/example" {
		t.Errorf("Repository = %q, want acme/example", claims.Repository)
	}
	if claims.SHA != "abc123" {
		t.Errorf("SHA = %q, want abc123", claims.SHA)
	}
}

func TestVerify_TamperedPayloadFailsSignature(t *testing.T) {
	now := time.Now()
	token, jwks, _ := signTestToken(t, validClaims(now), "test-key-1")

	parts := splitJWT(t, token)
	tamperedClaims := validClaims(now)
	tamperedClaims.Repository = "attacker/malicious" // tampering attempt
	tamperedJSON, _ := json.Marshal(tamperedClaims)
	tamperedPayload := base64.RawURLEncoding.EncodeToString(tamperedJSON)

	tamperedToken := parts[0] + "." + tamperedPayload + "." + parts[2]

	if _, err := Verify(tamperedToken, jwks, VerifyOptions{Now: now}); err == nil {
		t.Fatal("Verify() with a tampered payload should fail signature verification, got nil error")
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	now := time.Now()
	claims := validClaims(now)
	claims.ExpiresAt = now.Add(-time.Minute).Unix() // already expired
	token, jwks, _ := signTestToken(t, claims, "test-key-1")

	if _, err := Verify(token, jwks, VerifyOptions{Now: now}); err == nil {
		t.Fatal("Verify() with an expired token should fail, got nil error")
	}
}

func TestVerify_WrongAudience(t *testing.T) {
	now := time.Now()
	token, jwks, _ := signTestToken(t, validClaims(now), "test-key-1")

	if _, err := Verify(token, jwks, VerifyOptions{ExpectedAudience: "https://not-the-right-audience", Now: now}); err == nil {
		t.Fatal("Verify() with the wrong expected audience should fail, got nil error")
	}
}

func TestVerify_WrongIssuer(t *testing.T) {
	now := time.Now()
	claims := validClaims(now)
	claims.Issuer = "https://not-github.example.com"
	token, jwks, _ := signTestToken(t, claims, "test-key-1")

	if _, err := Verify(token, jwks, VerifyOptions{Now: now}); err == nil {
		t.Fatal("Verify() with a non-GitHub issuer should fail, got nil error")
	}
}

func TestVerify_UnknownKeyID(t *testing.T) {
	now := time.Now()
	token, jwks, _ := signTestToken(t, validClaims(now), "test-key-1")
	jwks.Keys[0].Kid = "a-different-key-id" // simulate the signing key not being in the JWKS

	if _, err := Verify(token, jwks, VerifyOptions{Now: now}); err == nil {
		t.Fatal("Verify() with no matching key in the JWKS should fail, got nil error")
	}
}

func splitJWT(t *testing.T, token string) []string {
	t.Helper()
	parts := make([]string, 0, 3)
	start := 0
	for i, c := range token {
		if c == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	if len(parts) != 3 {
		t.Fatalf("token %q does not have 3 parts", token)
	}
	return parts
}
