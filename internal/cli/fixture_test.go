package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shihasz/warden/internal/provenance/attest"
	"github.com/Shihasz/warden/internal/provenance/dsse"
	"github.com/Shihasz/warden/internal/provenance/oidc"
	"github.com/Shihasz/warden/internal/provenance/oidc/oidctest"
)

const (
	fixtureRepository = "acme/example"
	fixtureRef        = "refs/heads/main"
)

type tokenKind int

const (
	// tokenBound is the legitimate case: a GitHub-signed token naming the
	// signing key. It is the zero value, so it is the default.
	tokenBound tokenKind = iota
	// tokenNone embeds no token. A forged statement looks exactly like this.
	tokenNone
	// tokenForOtherKey is GitHub-signed, but its audience names a different key.
	tokenForOtherKey
	// tokenFromStranger is signed by a key GitHub doesn't publish.
	tokenFromStranger
)

type fixtureConfig struct {
	token tokenKind
	// tokenRepository, if set, mints the token for a different repository
	// than the one the statement claims.
	tokenRepository string
}

type attestationFixture struct {
	attestationPath string
	pubKeyPath      string
	artifactPath    string
	jwksPath        string
}

func fixtureClaims(audienceKey ed25519.PublicKey, repository string) oidc.Claims {
	issued := time.Now().Add(-2 * time.Hour) // long expired, like a real release's token
	return oidc.Claims{
		Issuer:            oidc.Issuer,
		Audience:          attest.BindingAudience(audienceKey),
		ExpiresAt:         issued.Add(time.Hour).Unix(),
		NotBefore:         issued.Unix(),
		IssuedAt:          issued.Unix(),
		Repository:        repository,
		Ref:               fixtureRef,
		SHA:               "abc123def456",
		Workflow:          "ci",
		WorkflowRef:       fixtureRepository + "/.github/workflows/ci.yml@" + fixtureRef,
		JobWorkflowRef:    fixtureRepository + "/.github/workflows/ci.yml@" + fixtureRef,
		RunID:             "987654321",
		RunnerEnvironment: "github-hosted",
		EventName:         "push",
		Actor:             "octocat",
	}
}

// newAttestationFixture writes a complete, really-signed attestation (and
// the artifact, public key, and JWKS around it) to a temp directory.
func newAttestationFixture(t *testing.T, cfg fixtureConfig) attestationFixture {
	t.Helper()
	dir := t.TempDir()

	artifactPath := filepath.Join(dir, "artifact")
	if err := os.WriteFile(artifactPath, []byte("real artifact bytes"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	github := oidctest.NewSigner(t, "kid-1")
	jwksPath := filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(jwksPath, github.JWKSJSON(t), 0o644); err != nil {
		t.Fatalf("write JWKS: %v", err)
	}

	stmtClaims := fixtureClaims(pub, fixtureRepository)
	tokenClaims := stmtClaims
	if cfg.tokenRepository != "" {
		tokenClaims.Repository = cfg.tokenRepository
	}

	opts := attest.BuildOptions{ArtifactPath: artifactPath, ArtifactName: "artifact"}
	switch cfg.token {
	case tokenBound:
		opts.OIDCToken = github.Sign(t, tokenClaims)
	case tokenForOtherKey:
		otherPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey() error = %v", err)
		}
		tokenClaims.Audience = attest.BindingAudience(otherPub)
		opts.OIDCToken = github.Sign(t, tokenClaims)
	case tokenFromStranger:
		opts.OIDCToken = oidctest.NewSigner(t, "kid-1").Sign(t, tokenClaims)
	case tokenNone:
	}

	stmt, err := attest.BuildStatement(&stmtClaims, opts)
	if err != nil {
		t.Fatalf("BuildStatement() error = %v", err)
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	env, err := dsse.Sign("application/vnd.in-toto+json", payload, priv, dsse.KeyID(pub))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	attestationPath := filepath.Join(dir, "artifact.intoto.jsonl")
	if err := os.WriteFile(attestationPath, append(envJSON, '\n'), 0o644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	pubPEM, err := encodePublicKeyPEM(pub)
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	pubKeyPath := filepath.Join(dir, "artifact.intoto.jsonl.pub")
	if err := os.WriteFile(pubKeyPath, pubPEM, 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	return attestationFixture{
		attestationPath: attestationPath,
		pubKeyPath:      pubKeyPath,
		artifactPath:    artifactPath,
		jwksPath:        jwksPath,
	}
}

func runCLI(t *testing.T, args ...string) (stderr string, err error) {
	t.Helper()
	root := NewRootCmd("test")
	var stdout, errBuf bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err = root.Execute()
	return errBuf.String(), err
}

// requireErrContains fails unless err mentions want. Failure tests must
// assert on the message, so they can't pass for the wrong reason.
func requireErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q (it may be failing for the wrong reason)", err.Error(), want)
	}
}
