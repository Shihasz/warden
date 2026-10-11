package cli

import (
	"bytes"
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

func TestLoadProvenanceInput_NoAttestationFlag(t *testing.T) {
	cmd, _ := newStderrCmd()

	got, err := loadProvenanceInput(cmd, &policyCheckOptions{})
	if err != nil {
		t.Fatalf("loadProvenanceInput() error = %v", err)
	}
	if got.Verified {
		t.Error("Verified = true with no attestation configured, want false")
	}
}

func TestLoadProvenanceInput_ValidAttestation(t *testing.T) {
	attestationPath, pubKeyPath, artifactPath := writeSignedFixture(t, []byte("real artifact bytes"), "https://github.com/acme/example", "refs/heads/main")
	cmd, stderr := newStderrCmd()

	got, err := loadProvenanceInput(cmd, &policyCheckOptions{
		attestationPath: attestationPath,
		pubKeyPath:      pubKeyPath,
		artifactPath:    artifactPath,
	})
	if err != nil {
		t.Fatalf("loadProvenanceInput() error = %v", err)
	}
	if !got.Verified || got.Statement == nil {
		t.Fatalf("Verified = %v, Statement nil = %v, want a verified statement; stderr: %s", got.Verified, got.Statement == nil, stderr.String())
	}
}

func TestLoadProvenanceInput_TamperedArtifactIsUnverified(t *testing.T) {
	attestationPath, pubKeyPath, artifactPath := writeSignedFixture(t, []byte("real artifact bytes"), "https://github.com/acme/example", "refs/heads/main")
	if err := os.WriteFile(artifactPath, []byte("swapped after signing"), 0o644); err != nil {
		t.Fatalf("overwrite artifact: %v", err)
	}
	cmd, stderr := newStderrCmd()

	got, err := loadProvenanceInput(cmd, &policyCheckOptions{
		attestationPath: attestationPath,
		pubKeyPath:      pubKeyPath,
		artifactPath:    artifactPath,
	})
	if err != nil {
		t.Fatalf("loadProvenanceInput() error = %v, want nil (unverified is a policy input, not a crash)", err)
	}
	if got.Verified {
		t.Error("Verified = true for a tampered artifact, want false")
	}
	if !strings.Contains(stderr.String(), "does not match") {
		t.Errorf("stderr = %q, want it to explain the digest mismatch", stderr.String())
	}
}

func TestLoadProvenanceInput_MissingAttestationFileIsUnverified(t *testing.T) {
	_, pubKeyPath, _ := writeSignedFixture(t, []byte("real artifact bytes"), "https://github.com/acme/example", "refs/heads/main")
	cmd, stderr := newStderrCmd()

	got, err := loadProvenanceInput(cmd, &policyCheckOptions{
		attestationPath: filepath.Join(t.TempDir(), "does-not-exist.intoto.jsonl"),
		pubKeyPath:      pubKeyPath,
	})
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
	attestationPath, _, _ := writeSignedFixture(t, []byte("real artifact bytes"), "https://github.com/acme/example", "refs/heads/main")
	cmd, stderr := newStderrCmd()

	got, err := loadProvenanceInput(cmd, &policyCheckOptions{
		attestationPath: attestationPath,
		pubKeyPath:      filepath.Join(t.TempDir(), "does-not-exist.pub"),
	})
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
// as a file is still a configuration mistake and must stay a hard error.
func TestLoadProvenanceInput_UnreadableAttestationStaysHardError(t *testing.T) {
	_, pubKeyPath, _ := writeSignedFixture(t, []byte("real artifact bytes"), "https://github.com/acme/example", "refs/heads/main")
	cmd, _ := newStderrCmd()

	_, err := loadProvenanceInput(cmd, &policyCheckOptions{
		attestationPath: t.TempDir(), // a directory, not a file
		pubKeyPath:      pubKeyPath,
	})
	if err == nil {
		t.Fatal("loadProvenanceInput() with a directory as the attestation path should return an error, got nil")
	}
}
