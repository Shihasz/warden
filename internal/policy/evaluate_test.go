package policy

import (
	"testing"

	"github.com/Shihasz/warden/internal/license/depsdev"
	"github.com/Shihasz/warden/internal/provenance/attest"
	"github.com/Shihasz/warden/internal/sbom"
	"github.com/Shihasz/warden/internal/vuln"
	"github.com/Shihasz/warden/internal/vuln/osv"
)

// criticalVector and mediumVector are the same two hand-verified CVSS
// vectors used in the cvss package's own tests — reusing known-correct
// values here means a failure in these tests points at the policy
// engine's logic, not at uncertainty over whether the input severity is
// even correct.
const (
	criticalVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" // -> 9.8, critical
	mediumVector   = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" // -> 6.5, medium
)

func findingWith(name string, vector string, knownExploited bool) vuln.ComponentFinding {
	return vuln.ComponentFinding{
		Component: sbom.Component{Name: name, Version: "1.0.0"},
		Vulnerabilities: []vuln.VulnResult{
			{
				Vulnerability: osv.Vulnerability{
					ID: "OSV-TEST-1",
					Severity: []struct {
						Type  string `json:"type"`
						Score string `json:"score"`
					}{{Type: "CVSS_V3", Score: vector}},
				},
				KnownExploited: knownExploited,
			},
		},
	}
}

func TestEvaluateVulnerabilities_SeverityThreshold(t *testing.T) {
	p := VulnerabilityPolicy{DenySeverity: "critical"}

	findings := []vuln.ComponentFinding{
		findingWith("critical-pkg", criticalVector, false),
		findingWith("medium-pkg", mediumVector, false),
	}

	violations := evaluateVulnerabilities(p, findings)
	if len(violations) != 1 {
		t.Fatalf("got %d violations, want 1 (only the critical one should be denied); violations: %+v", len(violations), violations)
	}
	if violations[0].Subject != "critical-pkg@1.0.0" {
		t.Errorf("violation subject = %q, want critical-pkg@1.0.0", violations[0].Subject)
	}
}

func TestEvaluateVulnerabilities_RequireKnownExploit(t *testing.T) {
	p := VulnerabilityPolicy{DenySeverity: "critical", RequireKnownExploit: true}

	findings := []vuln.ComponentFinding{
		findingWith("critical-not-exploited", criticalVector, false),
		findingWith("critical-exploited", criticalVector, true),
	}

	violations := evaluateVulnerabilities(p, findings)
	if len(violations) != 1 {
		t.Fatalf("got %d violations, want 1 (only the known-exploited one should be denied); violations: %+v", len(violations), violations)
	}
	if violations[0].Subject != "critical-exploited@1.0.0" {
		t.Errorf("violation subject = %q, want critical-exploited@1.0.0", violations[0].Subject)
	}
}

func TestEvaluateVulnerabilities_DisabledRule(t *testing.T) {
	p := VulnerabilityPolicy{} // DenySeverity empty — rule disabled
	findings := []vuln.ComponentFinding{findingWith("critical-pkg", criticalVector, true)}

	if violations := evaluateVulnerabilities(p, findings); len(violations) != 0 {
		t.Errorf("got %d violations with an empty DenySeverity, want 0 (rule should be disabled)", len(violations))
	}
}

func TestEvaluateVulnerabilities_UnknownSeverityNeverDenies(t *testing.T) {
	p := VulnerabilityPolicy{DenySeverity: "low"} // lowest threshold — would catch everything parseable
	findings := []vuln.ComponentFinding{findingWith("no-cvss-data-pkg", "", false)}

	if violations := evaluateVulnerabilities(p, findings); len(violations) != 0 {
		t.Errorf("got %d violations for a finding with no parseable CVSS data, want 0", len(violations))
	}
}

func TestEvaluateLicenses(t *testing.T) {
	p := LicensePolicy{DenyCategories: []string{"copyleft"}}

	results := []depsdev.LicenseResult{
		{Component: sbom.Component{Name: "mit-pkg", Version: "1.0.0"}, Licenses: []string{"MIT"}},
		{Component: sbom.Component{Name: "gpl-pkg", Version: "1.0.0"}, Licenses: []string{"GPL-3.0-only"}},
	}

	violations := evaluateLicenses(p, results)
	if len(violations) != 1 {
		t.Fatalf("got %d violations, want 1; violations: %+v", len(violations), violations)
	}
	if violations[0].Subject != "gpl-pkg@1.0.0" {
		t.Errorf("violation subject = %q, want gpl-pkg@1.0.0", violations[0].Subject)
	}
}

func TestEvaluateProvenance_RequiredButMissing(t *testing.T) {
	p := ProvenancePolicy{Required: true}
	violations := evaluateProvenance(p, ProvenanceInput{Verified: false})
	if len(violations) != 1 {
		t.Fatalf("got %d violations, want 1 (missing attestation)", len(violations))
	}
}

func TestEvaluateProvenance_NotRequiredAndMissing(t *testing.T) {
	p := ProvenancePolicy{Required: false}
	if violations := evaluateProvenance(p, ProvenanceInput{Verified: false}); len(violations) != 0 {
		t.Errorf("got %d violations when provenance isn't required, want 0", len(violations))
	}
}

func statementWithRunner(runnerEnv string) *attest.Statement {
	return &attest.Statement{
		Predicate: attest.Predicate{
			BuildDefinition: attest.BuildDefinition{
				ExternalParameters: map[string]string{
					"repository": "https://github.com/acme/example",
					"ref":        "refs/heads/main",
				},
				InternalParameters: map[string]string{"runnerEnvironment": runnerEnv},
			},
		},
	}
}

func TestEvaluateProvenance_MinLevel(t *testing.T) {
	p := ProvenancePolicy{Required: true, MinLevel: 2}

	selfHosted := ProvenanceInput{Verified: true, Statement: statementWithRunner("self-hosted")}
	if violations := evaluateProvenance(p, selfHosted); len(violations) != 1 {
		t.Errorf("self-hosted runner (level 1) against minLevel 2: got %d violations, want 1", len(violations))
	}

	githubHosted := ProvenanceInput{Verified: true, Statement: statementWithRunner("github-hosted")}
	if violations := evaluateProvenance(p, githubHosted); len(violations) != 0 {
		t.Errorf("github-hosted runner (level 2) against minLevel 2: got %d violations, want 0", len(violations))
	}
}

func TestEvaluateProvenance_IdentityMismatch(t *testing.T) {
	p := ProvenancePolicy{Required: true, ExpectedRepository: "https://github.com/different-org/different-repo"}
	prov := ProvenanceInput{Verified: true, Statement: statementWithRunner("github-hosted")}

	violations := evaluateProvenance(p, prov)
	if len(violations) != 1 {
		t.Fatalf("got %d violations for a repository mismatch, want 1", len(violations))
	}
}

func TestResult_Passed(t *testing.T) {
	if !(Result{}).Passed() {
		t.Error("Result{} with no violations should Pass()")
	}
	if (Result{Violations: []Violation{{}}}).Passed() {
		t.Error("Result with a violation should not Pass()")
	}
}
