package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shihasz/warden/internal/provenance/dsse"
)

func writeArtifact(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("fake binary content"), 0o644); err != nil {
		t.Fatalf("write fixture artifact: %v", err)
	}
	return path
}

func TestBindingAudience(t *testing.T) {
	pubA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	pubB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	a := BindingAudience(pubA)
	if !strings.HasPrefix(a, "warden:ed25519:") {
		t.Errorf("BindingAudience() = %q, want the warden:ed25519: prefix", a)
	}
	if !strings.HasSuffix(a, dsse.KeyID(pubA)) {
		t.Errorf("BindingAudience() = %q, want it to end with the key's fingerprint %s", a, dsse.KeyID(pubA))
	}
	if a != BindingAudience(pubA) {
		t.Error("BindingAudience() is not deterministic for the same key")
	}
	if a == BindingAudience(pubB) {
		t.Error("two different keys produced the same audience — the binding would not distinguish them")
	}
}

func TestBuildStatement_EmbedsOIDCToken(t *testing.T) {
	const token = "aaa.bbb.ccc"

	stmt, err := BuildStatement(testClaims(), BuildOptions{
		ArtifactPath: writeArtifact(t),
		ArtifactName: "warden",
		OIDCToken:    token,
		Now:          time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("BuildStatement() error = %v", err)
	}

	bp := stmt.Predicate.RunDetails.Byproducts
	if len(bp) != 1 {
		t.Fatalf("got %d byproducts, want 1", len(bp))
	}
	if bp[0].Name != OIDCTokenName || bp[0].MediaType != OIDCTokenMediaType {
		t.Errorf("byproduct = %q (%s), want %q (%s)", bp[0].Name, bp[0].MediaType, OIDCTokenName, OIDCTokenMediaType)
	}
	if string(bp[0].Content) != token {
		t.Errorf("byproduct content = %q, want %q", bp[0].Content, token)
	}

	// The SLSA spec says content is base64-encoded bytes on the wire.
	data, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	var wire struct {
		Predicate struct {
			RunDetails struct {
				Byproducts []struct {
					Content string `json:"content"`
				} `json:"byproducts"`
			} `json:"runDetails"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatalf("unmarshal statement: %v", err)
	}
	got := wire.Predicate.RunDetails.Byproducts
	want := base64.StdEncoding.EncodeToString([]byte(token))
	if len(got) != 1 || got[0].Content != want {
		t.Errorf("wire content = %+v, want a single entry %q (base64 of the token)", got, want)
	}
}

func TestBuildStatement_WithoutTokenHasNoByproducts(t *testing.T) {
	stmt, err := BuildStatement(testClaims(), BuildOptions{
		ArtifactPath: writeArtifact(t),
		ArtifactName: "warden",
	})
	if err != nil {
		t.Fatalf("BuildStatement() error = %v", err)
	}

	data, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	if strings.Contains(string(data), "byproducts") {
		t.Errorf("statement JSON contains byproducts with no token set: %s", data)
	}
}
