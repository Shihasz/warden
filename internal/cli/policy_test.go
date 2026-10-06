package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyCheck_RequiresSBOMFlag(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"policy", "check", "--policy", policyPath})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() with no --sbom flag should return an error, got nil")
	}
}

func TestPolicyCheck_RequiresPolicyFlag(t *testing.T) {
	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"policy", "check", "--sbom", sbomPath})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() with no --policy flag should return an error, got nil")
	}
}

func TestPolicyCheck_EmptySBOMComponents(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o644); err != nil {
		t.Fatalf("write sbom fixture: %v", err)
	}
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatalf("write policy fixture: %v", err)
	}

	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"policy", "check", "--sbom", sbomPath, "--policy", policyPath})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() with an SBOM that has zero components should return an error, got nil")
	}
}

func TestPolicyCheck_AttestationRequiresPubkey(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","components":[{"type":"library","name":"foo","version":"1.0.0"}]}`), 0o644); err != nil {
		t.Fatalf("write sbom fixture: %v", err)
	}
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatalf("write policy fixture: %v", err)
	}
	attestationPath := filepath.Join(dir, "fake.intoto.jsonl")
	if err := os.WriteFile(attestationPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write attestation fixture: %v", err)
	}

	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"policy", "check", "--sbom", sbomPath, "--policy", policyPath, "--attestation", attestationPath})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() with --attestation but no --pubkey should return an error, got nil")
	}
}

func TestPolicyCheck_MissingPolicyFile(t *testing.T) {
	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","components":[{"type":"library","name":"foo","version":"1.0.0"}]}`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"policy", "check", "--sbom", sbomPath, "--policy", "/nonexistent/policy.yaml"})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() with a nonexistent --policy file should return an error, got nil")
	}
}
