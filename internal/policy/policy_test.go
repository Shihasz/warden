package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func writePolicyFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestLoad(t *testing.T) {
	content := `
version: 1

vulnerabilities:
  denySeverity: critical
  requireKnownExploit: true

licenses:
  denyCategories:
    - copyleft

provenance:
  required: true
  minLevel: 2
  expectedRepository: "https://github.com/acme/example"
  expectedRef: "refs/heads/main"
`
	p, err := Load(writePolicyFixture(t, content))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if p.Vulnerabilities.DenySeverity != "critical" {
		t.Errorf("DenySeverity = %q, want critical", p.Vulnerabilities.DenySeverity)
	}
	if !p.Vulnerabilities.RequireKnownExploit {
		t.Error("RequireKnownExploit = false, want true")
	}
	if len(p.Licenses.DenyCategories) != 1 || p.Licenses.DenyCategories[0] != "copyleft" {
		t.Errorf("DenyCategories = %v, want [copyleft]", p.Licenses.DenyCategories)
	}
	if !p.Provenance.Required {
		t.Error("Provenance.Required = false, want true")
	}
	if p.Provenance.MinLevel != 2 {
		t.Errorf("MinLevel = %d, want 2", p.Provenance.MinLevel)
	}
	if p.Provenance.ExpectedRepository != "https://github.com/acme/example" {
		t.Errorf("ExpectedRepository = %q, want https://github.com/acme/example", p.Provenance.ExpectedRepository)
	}
}

func TestLoad_RejectsUnsupportedVersion(t *testing.T) {
	path := writePolicyFixture(t, "version: 2\n")
	if _, err := Load(path); err == nil {
		t.Fatal("Load() with an unsupported version should return an error, got nil")
	}
}

func TestLoad_RejectsMalformedYAML(t *testing.T) {
	path := writePolicyFixture(t, "version: 1\nvulnerabilities: [this is not a map]\n")
	if _, err := Load(path); err == nil {
		t.Fatal("Load() with malformed YAML (wrong type for a field) should return an error, got nil")
	}
}
