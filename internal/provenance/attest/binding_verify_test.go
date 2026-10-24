package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Shihasz/warden/internal/provenance/dsse"
	"github.com/Shihasz/warden/internal/provenance/oidc"
	"github.com/Shihasz/warden/internal/provenance/oidc/oidctest"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return pub, priv
}

// githubClaims returns the claims GitHub would sign for a run whose token
// names pub as its audience. The token is already expired on purpose: a
// release is verified long after its token's lifetime, so every test in
// this file also proves expiry is not what makes verification succeed.
func githubClaims(pub ed25519.PublicKey) oidc.Claims {
	issued := time.Now().Add(-2 * time.Hour)
	return oidc.Claims{
		Issuer:            oidc.Issuer,
		Audience:          BindingAudience(pub),
		ExpiresAt:         issued.Add(time.Hour).Unix(),
		NotBefore:         issued.Unix(),
		IssuedAt:          issued.Unix(),
		Repository:        "acme/example",
		Ref:               "refs/heads/main",
		SHA:               "abc123def456",
		Workflow:          "ci",
		WorkflowRef:       "acme/example/.github/workflows/ci.yml@refs/heads/main",
		JobWorkflowRef:    "acme/example/.github/workflows/ci.yml@refs/heads/main",
		RunID:             "987654321",
		RunnerEnvironment: "github-hosted",
		EventName:         "push",
		Actor:             "octocat",
	}
}

// buildBound builds a statement from stmtClaims embedding a token minted
// from tokenClaims by signer. Passing different claims models an attacker
// who holds a genuine token but claims a different identity.
func buildBound(t *testing.T, stmtClaims, tokenClaims oidc.Claims, signer *oidctest.Signer) *Statement {
	t.Helper()
	stmt, err := BuildStatement(&stmtClaims, BuildOptions{
		ArtifactPath: writeArtifact(t),
		ArtifactName: "warden",
		OIDCToken:    signer.Sign(t, tokenClaims),
	})
	if err != nil {
		t.Fatalf("BuildStatement() error = %v", err)
	}
	return stmt
}

func requireErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q (it may be failing for the wrong reason)", err.Error(), want)
	}
}

func TestVerifyBinding_Valid(t *testing.T) {
	pub, _ := newKey(t)
	signer := oidctest.NewSigner(t, "kid-1")
	claims := githubClaims(pub)
	if claims.ExpiresAt >= time.Now().Unix() {
		t.Fatal("test setup: the token must already be expired")
	}

	stmt := buildBound(t, claims, claims, signer)
	got, err := stmt.VerifyBinding(pub, signer.JWKS(t))
	if err != nil {
		t.Fatalf("VerifyBinding() error = %v", err)
	}
	if got.Repository != "acme/example" {
		t.Errorf("Repository = %q, want acme/example", got.Repository)
	}
}

func TestVerifyBinding_NoToken(t *testing.T) {
	pub, _ := newKey(t)
	signer := oidctest.NewSigner(t, "kid-1")
	claims := githubClaims(pub)

	stmt, err := BuildStatement(&claims, BuildOptions{ArtifactPath: writeArtifact(t), ArtifactName: "warden"})
	if err != nil {
		t.Fatalf("BuildStatement() error = %v", err)
	}
	if stmt.HasOIDCToken() {
		t.Error("HasOIDCToken() = true for a statement with no token")
	}
	if _, err := stmt.VerifyBinding(pub, signer.JWKS(t)); !errors.Is(err, ErrNoOIDCToken) {
		t.Errorf("VerifyBinding() error = %v, want ErrNoOIDCToken", err)
	}
}

func TestVerifyBinding_TokenNamesADifferentKey(t *testing.T) {
	pub, _ := newKey(t)
	otherPub, _ := newKey(t)
	signer := oidctest.NewSigner(t, "kid-1")

	// A genuine GitHub token, but minted for someone else's key.
	stmt := buildBound(t, githubClaims(pub), githubClaims(otherPub), signer)

	_, err := stmt.VerifyBinding(pub, signer.JWKS(t))
	requireErrContains(t, err, "audience")
}

func TestVerifyBinding_StatementDisagreesWithToken(t *testing.T) {
	pub, _ := newKey(t)
	signer := oidctest.NewSigner(t, "kid-1")

	// The attacker's genuine token is for their own repository, but the
	// statement they sign claims the victim's.
	tokenClaims := githubClaims(pub)
	tokenClaims.Repository = "attacker/other-repo"
	stmt := buildBound(t, githubClaims(pub), tokenClaims, signer)

	_, err := stmt.VerifyBinding(pub, signer.JWKS(t))
	requireErrContains(t, err, "disagrees")
	requireErrContains(t, err, "externalParameters.repository")
}

func TestVerifyBinding_TokenSignedByAStranger(t *testing.T) {
	pub, _ := newKey(t)
	github := oidctest.NewSigner(t, "kid-1")
	stranger := oidctest.NewSigner(t, "kid-1") // same kid, different key

	claims := githubClaims(pub)
	stmt := buildBound(t, claims, claims, stranger)

	_, err := stmt.VerifyBinding(pub, github.JWKS(t))
	requireErrContains(t, err, "signature")
}

func TestVerifyBinding_RejectsUnbackedExtraParameters(t *testing.T) {
	pub, _ := newKey(t)
	signer := oidctest.NewSigner(t, "kid-1")
	claims := githubClaims(pub)

	stmt := buildBound(t, claims, claims, signer)
	stmt.Predicate.BuildDefinition.ExternalParameters["injected"] = "x"

	_, err := stmt.VerifyBinding(pub, signer.JWKS(t))
	requireErrContains(t, err, "unexpected extra entry")
}

func TestVerifyBinding_RejectsAmbiguousTokens(t *testing.T) {
	pub, _ := newKey(t)
	signer := oidctest.NewSigner(t, "kid-1")
	claims := githubClaims(pub)

	stmt := buildBound(t, claims, claims, signer)
	bp := stmt.Predicate.RunDetails.Byproducts
	stmt.Predicate.RunDetails.Byproducts = append(bp, bp[0])

	_, err := stmt.VerifyBinding(pub, signer.JWKS(t))
	requireErrContains(t, err, "exactly 1")
}

// The token travels inside a signed, serialized envelope: this proves
// the embedded bytes survive the JSON/base64 round trip intact.
func TestBoundAttestation_EndToEnd(t *testing.T) {
	pub, priv := newKey(t)
	signer := oidctest.NewSigner(t, "kid-1")
	claims := githubClaims(pub)

	payload, err := json.Marshal(buildBound(t, claims, claims, signer))
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	env, err := dsse.Sign("application/vnd.in-toto+json", payload, priv, dsse.KeyID(pub))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	verified, err := VerifyEnvelope(env, pub)
	if err != nil {
		t.Fatalf("VerifyEnvelope() error = %v", err)
	}
	if _, err := verified.VerifyBinding(pub, signer.JWKS(t)); err != nil {
		t.Fatalf("VerifyBinding() after the envelope round trip error = %v", err)
	}
}
