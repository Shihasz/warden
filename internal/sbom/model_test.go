package sbom

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBOM_MarshalJSON(t *testing.T) {
	b := BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.7",
		SerialNumber: "urn:uuid:00000000-0000-0000-0000-000000000000",
		Version:      1,
		Metadata: Metadata{
			Timestamp: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC),
		},
		Components: []Component{
			{
				Type:    "library",
				Name:    "github.com/example/foo",
				Version: "v1.2.3",
				PURL:    "pkg:golang/github.com/example/foo@v1.2.3",
				Properties: []Property{
					{Name: "gomod:h1", Value: "h1:abcdef=="},
				},
			},
		},
	}

	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("round-trip Unmarshal() error = %v", err)
	}

	if got["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", got["bomFormat"])
	}
	if got["specVersion"] != "1.7" {
		t.Errorf("specVersion = %v, want 1.7", got["specVersion"])
	}

	components, ok := got["components"].([]any)
	if !ok || len(components) != 1 {
		t.Fatalf("components = %v, want a single-element array", got["components"])
	}
}
