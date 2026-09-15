package pip

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "requirements.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestParseRequirements(t *testing.T) {
	content := `
# a comment line, and a blank line above
requests==2.31.0
Flask_SQLAlchemy==3.1.1  # inline comment
numpy>=1.26  ; python_version >= "3.9"
django[bcrypt,argon2]==5.0.1
-r other-requirements.txt
-e ./local-package
git+https://github.com/example/foo.git#egg=foo
`
	result, err := ParseRequirements(writeFixture(t, content))
	if err != nil {
		t.Fatalf("ParseRequirements() error = %v", err)
	}

	if len(result.Components) != 4 {
		t.Fatalf("got %d components, want 4; components: %+v", len(result.Components), result.Components)
	}
	if len(result.Skipped) != 3 {
		t.Fatalf("got %d skipped lines, want 3 (-r, -e, git+); skipped: %+v", len(result.Skipped), result.Skipped)
	}

	byName := make(map[string]int)
	for i, c := range result.Components {
		byName[c.Name] = i
	}

	req, ok := byName["requests"]
	if !ok {
		t.Fatal("missing component 'requests'")
	}
	if result.Components[req].Version != "2.31.0" {
		t.Errorf("requests version = %q, want 2.31.0", result.Components[req].Version)
	}
	if result.Components[req].PURL != "pkg:pypi/requests@2.31.0" {
		t.Errorf("requests PURL = %q, want pkg:pypi/requests@2.31.0", result.Components[req].PURL)
	}

	flaskIdx, ok := byName["flask-sqlalchemy"]
	if !ok {
		t.Fatal("missing normalized component 'flask-sqlalchemy' (PEP 503 normalization failed)")
	}
	if result.Components[flaskIdx].Version != "3.1.1" {
		t.Errorf("flask-sqlalchemy version = %q, want 3.1.1", result.Components[flaskIdx].Version)
	}

	numpyIdx, ok := byName["numpy"]
	if !ok {
		t.Fatal("missing component 'numpy'")
	}
	numpy := result.Components[numpyIdx]
	if numpy.Version != "" {
		t.Errorf("numpy version = %q, want empty (unpinned range, not a resolvable version)", numpy.Version)
	}
	var numpyPinned, numpyMarker string
	for _, p := range numpy.Properties {
		if p.Name == "pip:pinned" {
			numpyPinned = p.Value
		}
		if p.Name == "pip:marker" {
			numpyMarker = p.Value
		}
	}
	if numpyPinned != "false" {
		t.Errorf("numpy pip:pinned = %q, want false", numpyPinned)
	}
	if numpyMarker != `python_version >= "3.9"` {
		t.Errorf("numpy pip:marker = %q, want the environment marker", numpyMarker)
	}

	if _, ok := byName["django"]; !ok {
		t.Fatal("missing component 'django' (extras should not prevent name/version parsing)")
	}
}
