package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shihasz/warden/internal/provenance/oidc"
)

func TestAttestSign_RequiresArtifactFlag(t *testing.T) {
	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"attest", "sign"})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() with no --artifact flag should return an error, got nil")
	}
}

func TestAttestSign_MissingArtifactFile(t *testing.T) {
	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"attest", "sign", "--artifact", "/nonexistent/path/binary"})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() with a nonexistent --artifact file should return an error, got nil")
	}
}

func TestAttestSign_MissingOIDCEnvVars(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake-artifact")
	if err := os.WriteFile(path, []byte("fake binary"), 0o644); err != nil {
		t.Fatalf("write fixture artifact: %v", err)
	}

	t.Setenv(oidc.EnvRequestURL, "")
	t.Setenv(oidc.EnvRequestToken, "")

	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"attest", "sign", "--artifact", path})

	err := root.Execute()
	if err == nil {
		t.Fatal("Execute() with no GitHub Actions OIDC environment should return an error, got nil")
	}
	if !strings.Contains(err.Error(), oidc.EnvRequestURL) {
		t.Errorf("error = %q, want it to mention %s so someone running this locally understands why it failed", err.Error(), oidc.EnvRequestURL)
	}
}
