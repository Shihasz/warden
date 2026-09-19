package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestScan_RequiresSBOMFlag(t *testing.T) {
	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan"})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() with no --sbom flag should return an error, got nil")
	}
}

func TestScan_MissingSBOMFile(t *testing.T) {
	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--sbom", "/nonexistent/path/sbom.json"})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() with a nonexistent --sbom file should return an error, got nil")
	}
}

func TestScan_EmptySBOMComponents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-sbom.json")
	if err := os.WriteFile(path, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--sbom", path})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() with an SBOM that has zero components should return an error, got nil")
	}
}
