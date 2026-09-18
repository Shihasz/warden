// Package vuln combines OSV.dev vulnerability data with the CISA KEV
// catalog, answering both "is this component vulnerable" (OSV) and "is
// that vulnerability actually being exploited" (KEV) for each SBOM
// component.
package vuln

import (
	"context"

	"github.com/Shihasz/warden/internal/sbom"
	"github.com/Shihasz/warden/internal/vuln/kev"
	"github.com/Shihasz/warden/internal/vuln/osv"
)

// VulnResult is one OSV vulnerability, annotated with whether it's known
// to be actively exploited per CISA's KEV catalog.
type VulnResult struct {
	osv.Vulnerability
	KnownExploited bool `json:"knownExploited"`
}

// ComponentFinding pairs a component with its annotated vulnerabilities.
type ComponentFinding struct {
	Component       sbom.Component `json:"component"`
	Vulnerabilities []VulnResult   `json:"vulnerabilities"`
}

// Scan queries OSV for the given components and merges the results with
// the KEV catalog's known-exploited status.
func Scan(ctx context.Context, client *osv.Client, catalog *kev.Catalog, components []sbom.Component) ([]ComponentFinding, []osv.Skipped, error) {
	findings, skipped, err := client.Scan(ctx, components)
	if err != nil {
		return nil, nil, err
	}
	return Merge(findings, catalog), skipped, nil
}

// Merge cross-references OSV findings against the KEV catalog, marking
// each vulnerability whose CVE alias appears in KEV as known-exploited.
// A nil catalog is treated as "nothing is known-exploited" rather than
// an error — callers that intentionally skip KEV entirely still get a
// usable result.
func Merge(findings []osv.Finding, catalog *kev.Catalog) []ComponentFinding {
	results := make([]ComponentFinding, 0, len(findings))
	for _, f := range findings {
		vulns := make([]VulnResult, 0, len(f.Vulns))
		for _, v := range f.Vulns {
			vulns = append(vulns, VulnResult{
				Vulnerability:  v,
				KnownExploited: isKnownExploited(v, catalog),
			})
		}
		results = append(results, ComponentFinding{Component: f.Component, Vulnerabilities: vulns})
	}
	return results
}

func isKnownExploited(v osv.Vulnerability, catalog *kev.Catalog) bool {
	if catalog == nil {
		return false
	}
	for _, alias := range v.Aliases {
		if catalog.IsKnownExploited(alias) {
			return true
		}
	}
	return false
}
