package policy

import (
	"strings"
	"testing"

	"github.com/Shihasz/warden/internal/license/depsdev"
	"github.com/Shihasz/warden/internal/sbom"
	"github.com/Shihasz/warden/internal/vuln/osv"
)

func vulnOnly() *Policy {
	return &Policy{Vulnerabilities: VulnerabilityPolicy{DenySeverity: "critical"}}
}

func licenseOnly() *Policy {
	return &Policy{Licenses: LicensePolicy{DenyCategories: []string{"copyleft"}}}
}

func bothRules() *Policy {
	p := vulnOnly()
	p.Licenses = LicensePolicy{DenyCategories: []string{"copyleft"}}
	return p
}

func unpinned() sbom.Component {
	return sbom.Component{Name: "requests", PURL: "pkg:pypi/requests"}
}

func TestEvaluate_UnevaluatedComponentDeniesByDefault(t *testing.T) {
	res := Evaluate(vulnOnly(), Inputs{
		VulnSkipped: []osv.Skipped{{Component: unpinned(), Reason: "no resolved version to query"}},
	})

	if res.Passed() || len(res.Violations) != 1 {
		t.Fatalf("got %+v, want exactly one violation", res)
	}
	v := res.Violations[0]
	if v.Rule != "coverage" || v.Subject != "requests" {
		t.Errorf("violation = %+v, want a coverage violation for requests", v)
	}
	for _, want := range []string{"vulnerability scan", "no resolved version to query"} {
		if !strings.Contains(v.Message, want) {
			t.Errorf("message %q does not contain %q", v.Message, want)
		}
	}
}

func TestEvaluate_CoverageOnlyCountsRulesThatAreOn(t *testing.T) {
	// A vulnerability-scan gap means nothing to a policy with no vulnerability rule.
	res := Evaluate(licenseOnly(), Inputs{
		VulnSkipped: []osv.Skipped{{Component: unpinned(), Reason: "no resolved version to query"}},
	})
	if !res.Passed() || len(res.Warnings) != 0 {
		t.Errorf("got %+v, want no violations or warnings for a rule that is off", res)
	}

	// And a license-lookup gap means nothing to a policy with no license rule.
	res = Evaluate(vulnOnly(), Inputs{
		LicenseSkipped: []depsdev.Skipped{{Component: unpinned(), Reason: "deps.dev lookup failed: boom"}},
	})
	if !res.Passed() {
		t.Errorf("got %+v, want no violations for a rule that is off", res)
	}
}

func TestEvaluate_OneViolationPerComponent(t *testing.T) {
	a := sbom.Component{Name: "alpha", Version: "1.0.0", PURL: "pkg:pypi/alpha@1.0.0"}
	b := sbom.Component{Name: "beta", PURL: "pkg:pypi/beta"}

	res := Evaluate(bothRules(), Inputs{
		VulnSkipped: []osv.Skipped{
			{Component: b, Reason: "no resolved version to query"},
			{Component: a, Reason: "r1"},
		},
		LicenseSkipped: []depsdev.Skipped{{Component: a, Reason: "deps.dev lookup failed: boom"}},
	})

	if len(res.Violations) != 2 {
		t.Fatalf("got %d violations, want 2 (one per component): %+v", len(res.Violations), res.Violations)
	}
	if res.Violations[0].Subject != "beta" || res.Violations[1].Subject != "alpha@1.0.0" {
		t.Errorf("subjects = %q, %q; want beta then alpha@1.0.0 (first-seen order, version included)", res.Violations[0].Subject, res.Violations[1].Subject)
	}
	for _, want := range []string{"vulnerability scan", "license check"} {
		if !strings.Contains(res.Violations[1].Message, want) {
			t.Errorf("alpha's message %q should list every check that skipped it, including %q", res.Violations[1].Message, want)
		}
	}
}

func TestEvaluate_WarnModeRecordsButDoesNotFail(t *testing.T) {
	p := vulnOnly()
	p.Coverage.Unevaluated = "warn"

	res := Evaluate(p, Inputs{
		VulnSkipped: []osv.Skipped{{Component: unpinned(), Reason: "no resolved version to query"}},
	})
	if !res.Passed() || len(res.Violations) != 0 {
		t.Fatalf("got %+v, want warn mode to pass", res)
	}
	if len(res.Warnings) != 1 || res.Warnings[0].Subject != "requests" {
		t.Errorf("warnings = %+v, want one for requests", res.Warnings)
	}
}

func TestEvaluate_CoverageReasonsStayOnOneLine(t *testing.T) {
	res := Evaluate(licenseOnly(), Inputs{
		LicenseSkipped: []depsdev.Skipped{{Component: unpinned(), Reason: "deps.dev lookup failed: status 500:\nsimulated\noutage\n"}},
	})
	if len(res.Violations) != 1 || strings.Contains(res.Violations[0].Message, "\n") {
		t.Errorf("got %+v, want a single-line message", res.Violations)
	}
}

func TestLoad_CoverageSetting(t *testing.T) {
	valid := []string{
		"version: 1\nvulnerabilities:\n  denySeverity: high\ncoverage:\n  unevaluated: deny\n",
		"version: 1\nvulnerabilities:\n  denySeverity: high\ncoverage:\n  unevaluated: warn\n",
		"version: 1\nlicenses:\n  denyCategories: [copyleft]\ncoverage:\n  unevaluated: warn\n",
		"version: 1\nvulnerabilities:\n  denySeverity: high\n",
	}
	for _, content := range valid {
		if _, err := Load(writePolicyFixture(t, content)); err != nil {
			t.Errorf("Load(%q) error = %v, want it accepted", content, err)
		}
	}

	invalid := map[string]string{
		"unknown value":       "version: 1\nvulnerabilities:\n  denySeverity: high\ncoverage:\n  unevaluated: ignore\n",
		"wrong case":          "version: 1\nvulnerabilities:\n  denySeverity: high\ncoverage:\n  unevaluated: Deny\n",
		"no rule to apply to": "version: 1\ncoverage:\n  unevaluated: warn\n",
		"misspelled key":      "version: 1\nvulnerabilities:\n  denySeverity: high\ncoverage:\n  unevalated: warn\n",
	}
	for name, content := range invalid {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writePolicyFixture(t, content))
			if err == nil {
				t.Fatalf("Load() accepted:\n%s", content)
			}
			if !strings.Contains(err.Error(), "unevaluated") && !strings.Contains(err.Error(), "unevalated") {
				t.Errorf("error = %q, want it to name the setting", err.Error())
			}
		})
	}
}
