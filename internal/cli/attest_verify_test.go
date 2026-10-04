package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Shihasz/warden/internal/provenance/attest"
	"github.com/Shihasz/warden/internal/provenance/dsse"
)

// writeSignedFixture builds and signs a real statement for artifactContent
// using a freshly generated key — bypassing OIDC entirely, since these
// tests are about verify's own logic, not about re-proving sign works
// (that's already covered elsewhere).
func writeSignedFixture(t *testing.T, artifactContent []byte, repo, ref string) (attestationPath, pubKeyPath, artifactPath string) {
	t.Helper()
	dir := t.TempDir()

	artifactPath = filepath.Join(dir, "artifact")
	if err := os.WriteFile(artifactPath, artifactContent, 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	sum := sha256.Sum256(artifactContent)
	stmt := attest.Statement{
		Type:          attest.StatementType,
		PredicateType: attest.SLSAProvenanceType,
		Subject: []attest.Subject{
			{Name: "artifact", Digest: map[string]string{"sha256": hex.EncodeToString(sum[:])}},
		},
		Predicate: attest.Predicate{
			BuildDefinition: attest.BuildDefinition{
				BuildType:          attest.BuildType,
				ExternalParameters: map[string]string{"repository": repo, "ref": ref},
			},
		},
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	env, err := dsse.Sign("application/vnd.in-toto+json", payload, priv, dsse.KeyID(pub))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	attestationPath = filepath.Join(dir, "artifact.intoto.jsonl")
	if err := os.WriteFile(attestationPath, append(envJSON, '\n'), 0o644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}

	pubPEM, err := encodePublicKeyPEM(pub)
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	pubKeyPath = filepath.Join(dir, "artifact.intoto.jsonl.pub")
	if err := os.WriteFile(pubKeyPath, pubPEM, 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	return attestationPath, pubKeyPath, artifactPath
}

func TestAttestVerify_Success(t *testing.T) {
	attestationPath, pubKeyPath, artifactPath := writeSignedFixture(t, []byte("real artifact bytes"), "https://github.com/acme/example", "refs/heads/main")

	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"attest", "verify",
		"--attestation", attestationPath,
		"--pubkey", pubKeyPath,
		"--artifact", artifactPath,
		"--expect-repository", "https://github.com/acme/example",
		"--expect-ref", "refs/heads/main",
	})

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, stderr = %s", err, stderr.String())
	}
}

func TestAttestVerify_FailsOnArtifactDigestMismatch(t *testing.T) {
	attestationPath, pubKeyPath, artifactPath := writeSignedFixture(t, []byte("real artifact bytes"), "https://github.com/acme/example", "refs/heads/main")

	// Simulate someone swapping the binary without re-signing.
	if err := os.WriteFile(artifactPath, []byte("a different, tampered artifact"), 0o644); err != nil {
		t.Fatalf("overwrite artifact: %v", err)
	}

	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"attest", "verify",
		"--attestation", attestationPath,
		"--pubkey", pubKeyPath,
		"--artifact", artifactPath,
	})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() with a mismatched artifact digest should return an error, got nil")
	}
}

func TestAttestVerify_FailsOnWrongExpectedRepository(t *testing.T) {
	attestationPath, pubKeyPath, _ := writeSignedFixture(t, []byte("real artifact bytes"), "https://github.com/acme/example", "refs/heads/main")

	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"attest", "verify",
		"--attestation", attestationPath,
		"--pubkey", pubKeyPath,
		"--expect-repository", "https://github.com/some-other-org/different-repo",
	})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() with a mismatched expected repository should return an error, got nil")
	}
}

func TestAttestVerify_FailsOnWrongPublicKey(t *testing.T) {
	attestationPath, _, _ := writeSignedFixture(t, []byte("real artifact bytes"), "https://github.com/acme/example", "refs/heads/main")

	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	wrongPubPEM, err := encodePublicKeyPEM(wrongPub)
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	wrongPubKeyPath := filepath.Join(t.TempDir(), "wrong.pub")
	if err := os.WriteFile(wrongPubKeyPath, wrongPubPEM, 0o644); err != nil {
		t.Fatalf("write wrong public key: %v", err)
	}

	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"attest", "verify",
		"--attestation", attestationPath,
		"--pubkey", wrongPubKeyPath,
	})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() with the wrong public key (not the one that actually signed this attestation) should return an error, got nil")
	}
}
