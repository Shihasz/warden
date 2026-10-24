package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func verifyArgs(f attestationFixture, extra ...string) []string {
	args := []string{
		"attest", "verify",
		"--attestation", f.attestationPath,
		"--pubkey", f.pubKeyPath,
		"--jwks-file", f.jwksPath,
	}
	return append(args, extra...)
}

func TestAttestVerify_Success(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{})

	stderr, err := runCLI(t, verifyArgs(f,
		"--artifact", f.artifactPath,
		"--expect-repository", "https://github.com/acme/example",
		"--expect-ref", "refs/heads/main",
	)...)
	if err != nil {
		t.Fatalf("Execute() error = %v, stderr = %s", err, stderr)
	}
	if !strings.Contains(stderr, "bound to a GitHub-signed identity") {
		t.Errorf("stderr = %q, want it to report the verified binding", stderr)
	}
}

// This is the forged-statement attack: a valid signature over claims that
// nothing ties to GitHub.
func TestAttestVerify_RejectsUnboundAttestationByDefault(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{token: tokenNone})

	_, err := runCLI(t, verifyArgs(f)...)
	requireErrContains(t, err, "no embedded GitHub OIDC token")
}

func TestAttestVerify_AllowUnboundAcceptsWithAWarning(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{token: tokenNone})

	stderr, err := runCLI(t, verifyArgs(f, "--allow-unbound")...)
	if err != nil {
		t.Fatalf("Execute() error = %v, stderr = %s", err, stderr)
	}
	if !strings.Contains(stderr, "self-asserted") {
		t.Errorf("stderr = %q, want a warning that the claims are self-asserted", stderr)
	}
}

func TestAttestVerify_AllowUnboundDoesNotExcuseABadToken(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{token: tokenForOtherKey})

	_, err := runCLI(t, verifyArgs(f, "--allow-unbound")...)
	requireErrContains(t, err, "audience")
}

func TestAttestVerify_RejectsTokenNamingAnotherKey(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{token: tokenForOtherKey})

	_, err := runCLI(t, verifyArgs(f)...)
	requireErrContains(t, err, "audience")
}

func TestAttestVerify_RejectsStatementThatDisagreesWithToken(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{tokenRepository: "attacker/other-repo"})

	_, err := runCLI(t, verifyArgs(f)...)
	requireErrContains(t, err, "disagrees")
}

func TestAttestVerify_RejectsTokenSignedByAStranger(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{token: tokenFromStranger})

	_, err := runCLI(t, verifyArgs(f)...)
	requireErrContains(t, err, "signature")
}

func TestAttestVerify_FailsOnArtifactDigestMismatch(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{})
	if err := os.WriteFile(f.artifactPath, []byte("swapped after signing"), 0o644); err != nil {
		t.Fatalf("overwrite artifact: %v", err)
	}

	_, err := runCLI(t, verifyArgs(f, "--artifact", f.artifactPath)...)
	requireErrContains(t, err, "does not match any subject")
}

func TestAttestVerify_FailsOnWrongExpectedRepository(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{})

	_, err := runCLI(t, verifyArgs(f, "--expect-repository", "https://github.com/some-other-org/different-repo")...)
	requireErrContains(t, err, "does not match expected")
}

func TestAttestVerify_FailsOnWrongPublicKey(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{})

	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	wrongPEM, err := encodePublicKeyPEM(wrongPub)
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	f.pubKeyPath = filepath.Join(t.TempDir(), "wrong.pub")
	if err := os.WriteFile(f.pubKeyPath, wrongPEM, 0o644); err != nil {
		t.Fatalf("write wrong public key: %v", err)
	}

	_, err = runCLI(t, verifyArgs(f)...)
	requireErrContains(t, err, "signature")
}
