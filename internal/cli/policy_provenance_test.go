package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func newStderrCmd() (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{}
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	return cmd, &stderr
}

func optsFor(f attestationFixture) *policyCheckOptions {
	return &policyCheckOptions{
		attestationPath: f.attestationPath,
		pubKeyPath:      f.pubKeyPath,
		artifactPath:    f.artifactPath,
		jwksFile:        f.jwksPath,
	}
}

func TestLoadProvenanceInput_NoAttestationFlag(t *testing.T) {
	cmd, _ := newStderrCmd()

	got, err := loadProvenanceInput(context.Background(), cmd, &policyCheckOptions{})
	if err != nil {
		t.Fatalf("loadProvenanceInput() error = %v", err)
	}
	if got.Verified {
		t.Error("Verified = true with no attestation configured, want false")
	}
}

func TestLoadProvenanceInput_ValidBoundAttestation(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{})
	cmd, stderr := newStderrCmd()

	got, err := loadProvenanceInput(context.Background(), cmd, optsFor(f))
	if err != nil {
		t.Fatalf("loadProvenanceInput() error = %v", err)
	}
	if !got.Verified || got.Statement == nil {
		t.Fatalf("Verified = %v, Statement nil = %v, want a verified statement; stderr: %s", got.Verified, got.Statement == nil, stderr.String())
	}
}

// The gate must not accept a statement that merely carries a valid
// signature: that is exactly what a forgery looks like.
func TestLoadProvenanceInput_UnboundAttestationIsUnverified(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{token: tokenNone})
	cmd, stderr := newStderrCmd()

	got, err := loadProvenanceInput(context.Background(), cmd, optsFor(f))
	if err != nil {
		t.Fatalf("loadProvenanceInput() error = %v, want nil (unverified is a policy input, not a crash)", err)
	}
	if got.Verified {
		t.Error("Verified = true for an unbound attestation, want false")
	}
	if !strings.Contains(stderr.String(), "no embedded GitHub OIDC token") {
		t.Errorf("stderr = %q, want it to explain the missing binding", stderr.String())
	}
}

func TestLoadProvenanceInput_TokenNamingAnotherKeyIsUnverified(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{token: tokenForOtherKey})
	cmd, stderr := newStderrCmd()

	got, err := loadProvenanceInput(context.Background(), cmd, optsFor(f))
	if err != nil {
		t.Fatalf("loadProvenanceInput() error = %v, want nil", err)
	}
	if got.Verified {
		t.Error("Verified = true when the token names a different key, want false")
	}
	if !strings.Contains(stderr.String(), "audience") {
		t.Errorf("stderr = %q, want it to mention the audience mismatch", stderr.String())
	}
}

func TestLoadProvenanceInput_TamperedArtifactIsUnverified(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{})
	if err := os.WriteFile(f.artifactPath, []byte("swapped after signing"), 0o644); err != nil {
		t.Fatalf("overwrite artifact: %v", err)
	}
	cmd, stderr := newStderrCmd()

	got, err := loadProvenanceInput(context.Background(), cmd, optsFor(f))
	if err != nil {
		t.Fatalf("loadProvenanceInput() error = %v, want nil", err)
	}
	if got.Verified {
		t.Error("Verified = true for a tampered artifact, want false")
	}
	if !strings.Contains(stderr.String(), "does not match") {
		t.Errorf("stderr = %q, want it to explain the digest mismatch", stderr.String())
	}
}

func TestLoadProvenanceInput_MissingAttestationFileIsUnverified(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{})
	f.attestationPath = filepath.Join(t.TempDir(), "does-not-exist.intoto.jsonl")
	cmd, stderr := newStderrCmd()

	got, err := loadProvenanceInput(context.Background(), cmd, optsFor(f))
	if err != nil {
		t.Fatalf("loadProvenanceInput() error = %v, want nil (a missing attestation is for the policy to judge)", err)
	}
	if got.Verified {
		t.Error("Verified = true for a missing attestation file, want false")
	}
	if !strings.Contains(stderr.String(), "attestation file not found") {
		t.Errorf("stderr = %q, want it to say the attestation file was not found", stderr.String())
	}
}

func TestLoadProvenanceInput_MissingPublicKeyFileIsUnverified(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{})
	f.pubKeyPath = filepath.Join(t.TempDir(), "does-not-exist.pub")
	cmd, stderr := newStderrCmd()

	got, err := loadProvenanceInput(context.Background(), cmd, optsFor(f))
	if err != nil {
		t.Fatalf("loadProvenanceInput() error = %v, want nil", err)
	}
	if got.Verified {
		t.Error("Verified = true for a missing public key file, want false")
	}
	if !strings.Contains(stderr.String(), "public key file not found") {
		t.Errorf("stderr = %q, want it to say the public key file was not found", stderr.String())
	}
}

// Only "does not exist" is softened. A path that exists but can't be read
// as a file, or an explicit --jwks-file that doesn't exist, is a
// configuration mistake and must stay a hard error.
func TestLoadProvenanceInput_UnreadableAttestationStaysHardError(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{})
	f.attestationPath = t.TempDir() // a directory, not a file
	cmd, _ := newStderrCmd()

	if _, err := loadProvenanceInput(context.Background(), cmd, optsFor(f)); err == nil {
		t.Fatal("loadProvenanceInput() with a directory as the attestation path should return an error, got nil")
	}
}

func TestLoadProvenanceInput_MissingJWKSFileStaysHardError(t *testing.T) {
	f := newAttestationFixture(t, fixtureConfig{})
	f.jwksPath = filepath.Join(t.TempDir(), "does-not-exist.json")
	cmd, _ := newStderrCmd()

	_, err := loadProvenanceInput(context.Background(), cmd, optsFor(f))
	requireErrContains(t, err, "read JWKS file")
}
