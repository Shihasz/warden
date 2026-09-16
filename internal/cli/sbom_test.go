package cli

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSBOMGenerate_GoModOnly(t *testing.T) {
	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"sbom", "generate",
		"--go-mod", "../sbom/gomod/testdata/simple/go.mod",
		"--go-sum", "../sbom/gomod/testdata/simple/go.sum",
		"--name", "test-project",
	})

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, stderr = %s", err, stderr.String())
	}

	var bom struct {
		BOMFormat  string `json:"bomFormat"`
		Components []struct {
			Name string `json:"name"`
		} `json:"components"`
		Metadata struct {
			Component struct {
				Name string `json:"name"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, stdout.String())
	}

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", bom.BOMFormat)
	}
	if len(bom.Components) != 2 {
		t.Errorf("got %d components, want 2", len(bom.Components))
	}
	if bom.Metadata.Component.Name != "test-project" {
		t.Errorf("metadata.component.name = %q, want test-project", bom.Metadata.Component.Name)
	}
}

func TestSBOMGenerate_NoInputsErrors(t *testing.T) {
	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"sbom", "generate"})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() with no dependency-file flags should return an error, got nil")
	}
}
