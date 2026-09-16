package sbom

import (
	"regexp"
	"testing"
)

var uuidPattern = regexp.MustCompile(
	`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
)

func TestNewSerialNumber(t *testing.T) {
	a, err := NewSerialNumber()
	if err != nil {
		t.Fatalf("NewSerialNumber() error = %v", err)
	}

	if !uuidPattern.MatchString(a) {
		t.Errorf("NewSerialNumber() = %q, does not match expected UUID v4 shape (check version nibble is 4 and variant nibble is 8/9/a/b)", a)
	}

	b, err := NewSerialNumber()
	if err != nil {
		t.Fatalf("second NewSerialNumber() error = %v", err)
	}
	if a == b {
		t.Errorf("two calls returned the same value (%q) — random source may not be working", a)
	}
}
