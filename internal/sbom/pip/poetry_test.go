package pip

import (
	"strings"
	"testing"

	"github.com/Shihasz/warden/internal/sbom"
)

func TestParsePoetryLock(t *testing.T) {
	components, err := ParsePoetryLock("testdata/poetry/poetry.lock")
	if err != nil {
		t.Fatalf("ParsePoetryLock() error = %v", err)
	}

	if len(components) != 2 {
		t.Fatalf("got %d components, want 2", len(components))
	}

	byName := make(map[string]sbom.Component)
	for _, c := range components {
		byName[c.Name] = c
	}

	req, ok := byName["requests"]
	if !ok {
		t.Fatal("missing component 'requests'")
	}
	if req.Version != "2.31.0" {
		t.Errorf("requests version = %q, want 2.31.0", req.Version)
	}
	if req.PURL != "pkg:pypi/requests@2.31.0" {
		t.Errorf("requests PURL = %q, want pkg:pypi/requests@2.31.0", req.PURL)
	}

	var groups string
	var fileHashCount int
	for _, p := range req.Properties {
		if p.Name == "pip:groups" {
			groups = p.Value
		}
		if strings.HasPrefix(p.Name, "poetry:file:") {
			fileHashCount++
		}
	}
	if groups != "main" {
		t.Errorf("requests pip:groups = %q, want main", groups)
	}
	if fileHashCount != 2 {
		t.Errorf("requests has %d file-hash properties, want 2 (wheel + sdist)", fileHashCount)
	}

	pytest, ok := byName["pytest"]
	if !ok {
		t.Fatal("missing component 'pytest'")
	}
	var pytestGroups string
	for _, p := range pytest.Properties {
		if p.Name == "pip:groups" {
			pytestGroups = p.Value
		}
	}
	if pytestGroups != "dev" {
		t.Errorf("pytest pip:groups = %q, want dev", pytestGroups)
	}
}
