package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Shihasz/warden/internal/provenance/dsse"
)

func signTestStatement(t *testing.T, stmt Statement) (*dsse.Envelope, ed25519.PublicKey) {
	t.Helper()

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

	return env, pub
}

func testStatement(digest string) Statement {
	return Statement{
		Type:          StatementType,
		PredicateType: SLSAProvenanceType,
		Subject: []Subject{
			{Name: "artifact", Digest: map[string]string{"sha256": digest}},
		},
		Predicate: Predicate{
			BuildDefinition: BuildDefinition{
				BuildType:          BuildType,
				ExternalParameters: map[string]string{"repository": "https://github.com/acme/example", "ref": "refs/heads/main"},
			},
		},
	}
}

func TestVerifyEnvelope_Success(t *testing.T) {
	env, pub := signTestStatement(t, testStatement("deadbeef"))

	stmt, err := VerifyEnvelope(env, pub)
	if err != nil {
		t.Fatalf("VerifyEnvelope() error = %v", err)
	}
	if stmt.Subject[0].Digest["sha256"] != "deadbeef" {
		t.Errorf("subject digest = %q, want deadbeef", stmt.Subject[0].Digest["sha256"])
	}
}

func TestVerifyEnvelope_WrongKeyFails(t *testing.T) {
	env, _ := signTestStatement(t, testStatement("deadbeef"))

	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if _, err := VerifyEnvelope(env, wrongPub); err == nil {
		t.Fatal("VerifyEnvelope() with the wrong public key should fail, got nil error")
	}
}

func TestVerifyEnvelope_WrongPayloadType(t *testing.T) {
	env, pub := signTestStatement(t, testStatement("deadbeef"))
	env.PayloadType = "application/not-in-toto"

	if _, err := VerifyEnvelope(env, pub); err == nil {
		t.Fatal("VerifyEnvelope() with an unexpected payload type should fail, got nil error")
	}
}

func TestCheckArtifactDigest(t *testing.T) {
	content := []byte("real artifact bytes")
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])

	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	stmt := testStatement(digest)
	if err := stmt.CheckArtifactDigest(path); err != nil {
		t.Errorf("CheckArtifactDigest() with matching content error = %v, want nil", err)
	}

	tamperedPath := filepath.Join(t.TempDir(), "tampered")
	if err := os.WriteFile(tamperedPath, []byte("different content entirely"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := stmt.CheckArtifactDigest(tamperedPath); err == nil {
		t.Error("CheckArtifactDigest() with mismatched content should return an error, got nil")
	}
}

func TestCheckIdentity(t *testing.T) {
	stmt := testStatement("deadbeef")

	if err := stmt.CheckIdentity(ExpectedIdentity{Repository: "https://github.com/acme/example", Ref: "refs/heads/main"}); err != nil {
		t.Errorf("CheckIdentity() with matching identity error = %v, want nil", err)
	}
	if err := stmt.CheckIdentity(ExpectedIdentity{Repository: "https://github.com/different/repo"}); err == nil {
		t.Error("CheckIdentity() with mismatched repository should return an error, got nil")
	}
	if err := stmt.CheckIdentity(ExpectedIdentity{Ref: "refs/heads/not-main"}); err == nil {
		t.Error("CheckIdentity() with mismatched ref should return an error, got nil")
	}
	// Zero-value fields mean "don't check" — an empty ExpectedIdentity
	// should never fail regardless of the statement's actual identity.
	if err := stmt.CheckIdentity(ExpectedIdentity{}); err != nil {
		t.Errorf("CheckIdentity() with no constraints set error = %v, want nil", err)
	}
}
