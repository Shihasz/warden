package npm

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeLockFile marshals a packageLock struct to a temp file and returns
// its path. Building the fixture from the real struct (rather than a
// hand-typed JSON string) means we can't accidentally hand-craft an
// invalid base64 hash by typo.
func writeLockFile(t *testing.T, pl packageLock) string {
	t.Helper()
	data, err := json.Marshal(pl)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func sha512Integrity(data []byte) string {
	sum := sha512.Sum512(data)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

func TestParse(t *testing.T) {
	fooIntegrity := sha512Integrity([]byte("fake content for foo"))

	pl := packageLock{
		LockfileVersion: 3,
		Packages: map[string]lockPackage{
			"": {Name: "example-app", Version: "1.0.0"}, // root — must be skipped
			"node_modules/foo": {
				Version:   "2.1.0",
				Integrity: fooIntegrity,
				Dev:       false,
			},
			"node_modules/@scope/bar": {
				Version: "0.5.0",
				Dev:     true,
			},
			"node_modules/workspace-link": {
				Version: "1.0.0",
				Link:    true, // must be skipped
			},
		},
	}

	path := writeLockFile(t, pl)
	components, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(components) != 2 {
		t.Fatalf("got %d components, want 2 (root and link entries should be skipped)", len(components))
	}

	byName := make(map[string]int)
	for i, c := range components {
		byName[c.Name] = i
	}

	fooIdx, ok := byName["foo"]
	if !ok {
		t.Fatal("missing component 'foo'")
	}
	foo := components[fooIdx]

	if foo.PURL != "pkg:npm/foo@2.1.0" {
		t.Errorf("foo PURL = %q, want pkg:npm/foo@2.1.0", foo.PURL)
	}
	if len(foo.Hashes) != 1 {
		t.Fatalf("foo has %d hashes, want 1", len(foo.Hashes))
	}
	sum := sha512.Sum512([]byte("fake content for foo"))
	wantHex := hex.EncodeToString(sum[:])
	if foo.Hashes[0].Alg != "SHA-512" {
		t.Errorf("foo hash alg = %q, want SHA-512", foo.Hashes[0].Alg)
	}
	if foo.Hashes[0].Content != wantHex {
		t.Errorf("foo hash content = %q, want %q", foo.Hashes[0].Content, wantHex)
	}

	barIdx, ok := byName["@scope/bar"]
	if !ok {
		t.Fatal("missing component '@scope/bar'")
	}
	bar := components[barIdx]

	if bar.PURL != "pkg:npm/%40scope/bar@0.5.0" {
		t.Errorf("bar PURL = %q, want pkg:npm/%%40scope/bar@0.5.0", bar.PURL)
	}

	var barDev, fooDev string
	for _, p := range bar.Properties {
		if p.Name == "npm:dev" {
			barDev = p.Value
		}
	}
	for _, p := range foo.Properties {
		if p.Name == "npm:dev" {
			fooDev = p.Value
		}
	}
	if barDev != "true" {
		t.Errorf("bar npm:dev = %q, want true", barDev)
	}
	if fooDev != "false" {
		t.Errorf("foo npm:dev = %q, want false", fooDev)
	}
}

func TestParse_RejectsLegacyLockfile(t *testing.T) {
	path := writeLockFile(t, packageLock{LockfileVersion: 1})
	if _, err := Parse(path); err == nil {
		t.Fatal("Parse() with lockfileVersion 1 should return an error, got nil")
	}
}
