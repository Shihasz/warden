//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func countRule(vs []violation, rule string) int {
	n := 0
	for _, v := range vs {
		if v.Rule == rule {
			n++
		}
	}
	return n
}

const licensePolicy = "version: 1\nlicenses:\n  denyCategories: [copyleft]\n"

// An outage of the license data source must not let a denied license
// through. Before this was fixed, the failed lookups became "skipped"
// components that the license rule never looked at, so the gate passed.
func TestCoverage_LicenseLookupOutageFailsTheGate(t *testing.T) {
	l := newLab(t)
	l.useProject(t, "go-vuln")
	l.writeFile(t, "policy.yaml", licensePolicy)
	l.DepsDev.Licenses("go", "github.com/example/vulnlib", "v1.0.0", "GPL-3.0-only")
	l.DepsDev.Licenses("go", "github.com/example/safelib", "v1.5.0", "MIT")
	l.generateSBOM(t, "--go-mod", "go.mod", "--go-sum", "go.sum")

	// Control: with deps.dev healthy, the GPL dependency is denied.
	healthy := l.gate(t, "policy.yaml")
	if healthy.Passed || countRule(healthy.Violations, "license") != 1 {
		t.Fatalf("control failed: %+v", healthy)
	}

	l.Env["WARDEN_DEPSDEV_URL"] = failingServer(t, http.StatusInternalServerError).URL
	outage := l.gate(t, "policy.yaml")
	if outage.Passed {
		t.Fatal("the gate passed during a deps.dev outage")
	}
	if got := countRule(outage.Violations, "coverage"); got != 2 {
		t.Fatalf("got %d coverage violations, want 2 (both dependencies unchecked): %+v", got, outage.Violations)
	}
	for _, v := range outage.Violations {
		if !strings.Contains(v.Message, "license check") || !strings.Contains(v.Message, "deps.dev lookup failed") {
			t.Errorf("violation %+v should say which check failed and why", v)
		}
	}
}

// A dependency without an exact version can't be queried for
// vulnerabilities. It must show up as unexamined; it must not pass quietly.
func TestCoverage_UnpinnedPythonRequirementFailsTheGate(t *testing.T) {
	l := newLab(t)
	l.writeFile(t, "requirements.txt", "vulnpy>=1.0\nsafepy==3.0.0\n")
	l.writeFile(t, "policy.yaml", vulnerabilityPolicy(true))
	l.generateSBOM(t, "--pip-requirements", "requirements.txt")

	gate := l.gate(t, "policy.yaml")
	if gate.Passed {
		t.Fatal("the gate passed although a dependency was never scanned")
	}
	if len(gate.Violations) != 1 {
		t.Fatalf("got %d violations, want exactly 1 (only the unpinned one): %+v", len(gate.Violations), gate.Violations)
	}
	v := gate.Violations[0]
	if v.Rule != "coverage" || v.Subject != "vulnpy" {
		t.Errorf("violation = %+v, want a coverage violation for vulnpy", v)
	}
	for _, want := range []string{"vulnerability scan", "no resolved version"} {
		if !strings.Contains(v.Message, want) {
			t.Errorf("message %q does not contain %q", v.Message, want)
		}
	}
}

func TestCoverage_WarnModeReportsWithoutFailing(t *testing.T) {
	l := newLab(t)
	l.writeFile(t, "requirements.txt", "vulnpy>=1.0\n")
	l.writeFile(t, "policy.yaml", vulnerabilityPolicy(true)+"\ncoverage:\n  unevaluated: warn\n")
	l.generateSBOM(t, "--pip-requirements", "requirements.txt")

	gate := l.gate(t, "policy.yaml")
	if !gate.Passed {
		t.Fatalf("warn mode failed the gate: %+v", gate.Violations)
	}
	if len(gate.Warnings) != 1 || gate.Warnings[0].Subject != "vulnpy" {
		t.Errorf("warnings = %+v, want one for vulnpy, so the gap is visible in the result file", gate.Warnings)
	}
}

// A gap in a check the policy doesn't enable is irrelevant.
func TestCoverage_OnlyAppliesToEnabledRules(t *testing.T) {
	l := newLab(t)
	l.useProject(t, "go-vuln")
	l.writeFile(t, "policy.yaml", vulnerabilityPolicy(true)) // no license rule
	l.generateSBOM(t, "--go-mod", "go.mod", "--go-sum", "go.sum")

	l.Env["WARDEN_DEPSDEV_URL"] = failingServer(t, http.StatusInternalServerError).URL
	gate := l.gate(t, "policy.yaml")
	if !gate.Passed {
		t.Errorf("a license-data outage failed a policy with no license rule: %+v", gate.Violations)
	}
}

// A data source that never answers must be cut off by --timeout and still
// fail the gate, instead of hanging the pipeline or passing.
func TestCoverage_LicenseLookupHangFailsWithinTheTimeout(t *testing.T) {
	l := newLab(t)
	l.useProject(t, "go-vuln")
	l.writeFile(t, "policy.yaml", licensePolicy)
	l.generateSBOM(t, "--go-mod", "go.mod", "--go-sum", "go.sum")

	l.Env["WARDEN_DEPSDEV_URL"] = hangingServer(t).URL
	start := time.Now()
	res := l.run(t, "policy", "check", "--sbom", "sbom.json", "--policy", "policy.yaml", "--timeout", "3s")
	elapsed := time.Since(start)

	res.requireExit(t, 1)
	var out gateResult
	res.decode(t, &out)
	if got := countRule(out.Violations, "coverage"); got != 2 {
		t.Errorf("got %d coverage violations, want 2: %+v", got, out.Violations)
	}
	if elapsed > 15*time.Second {
		t.Errorf("took %s to give up, want it bounded near --timeout 3s", elapsed)
	}
}

func TestLicensesCheck_UnevaluatedComponentsFailTheCheck(t *testing.T) {
	l := newLab(t)
	l.useProject(t, "go-vuln")
	l.generateSBOM(t, "--go-mod", "go.mod", "--go-sum", "go.sum")
	l.Env["WARDEN_DEPSDEV_URL"] = failingServer(t, http.StatusInternalServerError).URL

	// A report with no deny rule has nothing to fail on.
	l.run(t, "licenses", "check", "--sbom", "sbom.json").requireExit(t, 0)

	// With a deny rule, components that couldn't be checked fail it.
	res := l.run(t, "licenses", "check", "--sbom", "sbom.json", "--deny-category", "copyleft")
	res.requireExit(t, 1)
	if !strings.Contains(res.stderr, "could not be checked") {
		t.Errorf("stderr = %q, want it to say components could not be checked", res.stderr)
	}

	// The explicit opt-out.
	l.run(t, "licenses", "check", "--sbom", "sbom.json", "--deny-category", "copyleft", "--allow-unevaluated").requireExit(t, 0)
}
