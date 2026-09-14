package gomod

import "testing"

func TestParse_Simple(t *testing.T) {
	components, err := Parse("testdata/simple/go.mod", "testdata/simple/go.sum")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(components) != 2 {
		t.Fatalf("got %d components, want 2", len(components))
	}

	byName := make(map[string]struct {
		version  string
		indirect string
		h1       string
		hasH1    bool
	})
	for _, c := range components {
		entry := byName[c.Name]
		entry.version = c.Version
		for _, p := range c.Properties {
			switch p.Name {
			case "gomod:indirect":
				entry.indirect = p.Value
			case "gomod:h1":
				entry.h1 = p.Value
				entry.hasH1 = true
			}
		}
		byName[c.Name] = entry
	}

	uuid, ok := byName["github.com/google/uuid"]
	if !ok {
		t.Fatal("missing github.com/google/uuid component")
	}
	if uuid.version != "v1.6.0" {
		t.Errorf("uuid version = %q, want v1.6.0", uuid.version)
	}
	if uuid.indirect != "false" {
		t.Errorf("uuid gomod:indirect = %q, want false", uuid.indirect)
	}
	if !uuid.hasH1 || uuid.h1 != "h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=" {
		t.Errorf("uuid gomod:h1 = %q (present=%v), want the h1 hash", uuid.h1, uuid.hasH1)
	}

	text, ok := byName["golang.org/x/text"]
	if !ok {
		t.Fatal("missing golang.org/x/text component")
	}
	if text.indirect != "true" {
		t.Errorf("x/text gomod:indirect = %q, want true", text.indirect)
	}
}
