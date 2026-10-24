package oidc

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestVerify_AllowExpired(t *testing.T) {
	now := time.Now()
	claims := validClaims(now)
	claims.ExpiresAt = now.Add(-time.Hour).Unix()
	token, jwks, _ := signTestToken(t, claims, "test-key-1")

	if _, err := Verify(token, jwks, VerifyOptions{Now: now}); err == nil {
		t.Fatal("an expired token must be rejected by default")
	}
	if _, err := Verify(token, jwks, VerifyOptions{Now: now, AllowExpired: true}); err != nil {
		t.Fatalf("Verify() with AllowExpired error = %v, want nil", err)
	}
}

func TestVerify_AllowExpiredStillChecksSignature(t *testing.T) {
	now := time.Now()
	claims := validClaims(now)
	claims.ExpiresAt = now.Add(-time.Hour).Unix()
	token, jwks, _ := signTestToken(t, claims, "test-key-1")

	parts := splitJWT(t, token)
	claims.Repository = "attacker/malicious"
	tampered, _ := json.Marshal(claims)
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(tampered) + "." + parts[2]

	if _, err := Verify(forged, jwks, VerifyOptions{Now: now, AllowExpired: true}); err == nil {
		t.Fatal("AllowExpired must not weaken signature verification")
	}
}

func TestParseJWKS(t *testing.T) {
	jwks, err := ParseJWKS([]byte(`{"keys":[{"kty":"RSA","kid":"k","n":"AQAB","e":"AQAB"}]}`))
	if err != nil {
		t.Fatalf("ParseJWKS() error = %v", err)
	}
	key, err := jwks.publicKey("k")
	if err != nil || key.E != 65537 {
		t.Fatalf("publicKey(k) = %v, %v; want exponent 65537", key, err)
	}

	for _, bad := range []string{`not json`, `{}`, `{"keys":[]}`} {
		if _, err := ParseJWKS([]byte(bad)); err == nil {
			t.Errorf("ParseJWKS(%q) should return an error", bad)
		}
	}
}
