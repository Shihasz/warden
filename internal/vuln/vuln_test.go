package vuln

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Shihasz/warden/internal/sbom"
	"github.com/Shihasz/warden/internal/vuln/kev"
	"github.com/Shihasz/warden/internal/vuln/osv"
)

// writeKEVFixture builds a real *kev.Catalog by writing a minimal KEV
// JSON file and loading it through kev.LoadFile — this exercises the
// same parsing path production code uses, rather than constructing a
// Catalog value directly (which the kev package's exported API doesn't
// even allow, since its fields are set by parsing).
func writeKEVFixture(t *testing.T, cveIDs ...string) *kev.Catalog {
	t.Helper()

	type kevVuln struct {
		CVEID string `json:"cveID"`
	}
	vulns := make([]kevVuln, len(cveIDs))
	for i, id := range cveIDs {
		vulns[i] = kevVuln{CVEID: id}
	}

	data, err := json.Marshal(struct {
		Vulnerabilities []kevVuln `json:"vulnerabilities"`
	}{Vulnerabilities: vulns})
	if err != nil {
		t.Fatalf("marshal KEV fixture: %v", err)
	}

	path := filepath.Join(t.TempDir(), "kev.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write KEV fixture: %v", err)
	}

	catalog, err := kev.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	return catalog
}

func TestMerge(t *testing.T) {
	catalog := writeKEVFixture(t, "CVE-2024-00001")

	findings := []osv.Finding{
		{
			Component: sbom.Component{Name: "exploited-pkg"},
			Vulns:     []osv.Vulnerability{{ID: "OSV-1", Aliases: []string{"CVE-2024-00001"}}},
		},
		{
			Component: sbom.Component{Name: "unexploited-pkg"},
			Vulns:     []osv.Vulnerability{{ID: "OSV-2", Aliases: []string{"CVE-2024-99999"}}},
		},
	}

	results := Merge(findings, catalog)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}

	byName := make(map[string]ComponentFinding)
	for _, r := range results {
		byName[r.Component.Name] = r
	}

	exploited := byName["exploited-pkg"]
	if len(exploited.Vulnerabilities) != 1 || !exploited.Vulnerabilities[0].KnownExploited {
		t.Errorf("exploited-pkg KnownExploited = %+v, want true", exploited.Vulnerabilities)
	}

	unexploited := byName["unexploited-pkg"]
	if len(unexploited.Vulnerabilities) != 1 || unexploited.Vulnerabilities[0].KnownExploited {
		t.Errorf("unexploited-pkg KnownExploited = %+v, want false", unexploited.Vulnerabilities)
	}
}

func TestMerge_NilCatalogIsNeverExploited(t *testing.T) {
	findings := []osv.Finding{
		{
			Component: sbom.Component{Name: "pkg"},
			Vulns:     []osv.Vulnerability{{ID: "OSV-1", Aliases: []string{"CVE-2024-00001"}}},
		},
	}

	results := Merge(findings, nil)
	if results[0].Vulnerabilities[0].KnownExploited {
		t.Error("KnownExploited should be false when catalog is nil, not panic or default true")
	}
}
