//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// TestPipeline_CleanProject runs the whole pipeline (sbom, scan, licenses,
// policy) through the real binary against a project with nothing wrong
// with it, and proves every external request went to the mocks.
func TestPipeline_CleanProject(t *testing.T) {
	l := newLab(t)
	l.useProject(t, "go-clean")
	// The repository's own policy for runs that have no provenance, so
	// this also exercises a file we actually ship.
	l.copyRepoFile(t, "../warden-policy-no-provenance.yaml", "policy.yaml")
	l.DepsDev.Licenses("go", "github.com/example/alpha", "v1.2.3", "MIT")
	l.DepsDev.Licenses("go", "github.com/example/beta", "v0.4.0", "Apache-2.0")

	// 1. SBOM
	l.run(t, "sbom", "generate", "--go-mod", "go.mod", "--go-sum", "go.sum", "--name", "goclean", "-o", "sbom.json").requireExit(t, 0)
	var bom struct {
		BOMFormat  string `json:"bomFormat"`
		Components []struct {
			Name string `json:"name"`
		} `json:"components"`
	}
	l.readJSON(t, "sbom.json", &bom)
	if bom.BOMFormat != "CycloneDX" || len(bom.Components) != 2 {
		t.Fatalf("SBOM = %+v, want a CycloneDX document with 2 components", bom)
	}

	// 2. Vulnerability scan: the mock knows of no vulnerabilities.
	scan := l.run(t, "scan", "--sbom", "sbom.json")
	scan.requireExit(t, 0)
	var scanOut struct {
		Findings []any `json:"findings"`
	}
	scan.decode(t, &scanOut)
	if len(scanOut.Findings) != 0 {
		t.Errorf("scan findings = %v, want none", scanOut.Findings)
	}
	// Redirected data sources must never be silent.
	for _, env := range []string{"WARDEN_OSV_URL", "WARDEN_DEPSDEV_URL", "WARDEN_KEV_URL"} {
		if !strings.Contains(scan.stderr, env) {
			t.Errorf("scan stderr does not announce %s:\n%s", env, scan.stderr)
		}
	}

	// 3. License check.
	lic := l.run(t, "licenses", "check", "--sbom", "sbom.json")
	lic.requireExit(t, 0)
	var licOut struct {
		Findings []struct {
			Category string `json:"category"`
		} `json:"findings"`
	}
	lic.decode(t, &licOut)
	if len(licOut.Findings) != 2 {
		t.Fatalf("license findings = %d, want 2", len(licOut.Findings))
	}
	for _, f := range licOut.Findings {
		if f.Category != "permissive" {
			t.Errorf("license category = %q, want permissive", f.Category)
		}
	}

	// 4. Policy gate.
	gate := l.run(t, "policy", "check", "--sbom", "sbom.json", "--policy", "policy.yaml")
	gate.requireExit(t, 0)
	var gateOut struct {
		Passed bool `json:"passed"`
	}
	gate.decode(t, &gateOut)
	if !gateOut.Passed {
		t.Errorf("policy check did not pass:\n%s", gate.stdout)
	}

	// Hermeticity: the mocks must have actually served the traffic. If the
	// endpoint overrides ever stop working, warden would fall through to
	// the real services, and this test could still "pass" without ever
	// having tested anything.
	if n := l.OSV.log.count(); n == 0 {
		t.Error("mock OSV received no requests: warden did not use WARDEN_OSV_URL")
	}
	if n := l.DepsDev.log.count(); n == 0 {
		t.Error("mock deps.dev received no requests: warden did not use WARDEN_DEPSDEV_URL")
	}
	// scan and policy check both need the catalog, but the second run must
	// be served from the cache: exactly one fetch.
	if n := l.KEV.log.count(); n != 1 {
		t.Errorf("mock KEV served %d requests, want exactly 1 (the second command should have used the cache)", n)
	}
}
