//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// failClosed runs the gate and requires that it neither passes nor
// produces a passing result.
func failClosed(t *testing.T, l *lab, extra ...string) result {
	t.Helper()
	args := append([]string{"policy", "check", "--sbom", "sbom.json", "--policy", "policy.yaml"}, extra...)
	res := l.run(t, args...)
	if res.exit == 0 {
		t.Fatalf("the gate passed\n--- stdout ---\n%s\n--- stderr ---\n%s", res.stdout, res.stderr)
	}
	if strings.Contains(res.stdout, `"passed": true`) {
		t.Fatalf("the gate produced a passing result while failing:\n%s", res.stdout)
	}
	return res
}

func vulnLab(t *testing.T) *lab {
	t.Helper()
	l := newLab(t)
	l.useProject(t, "go-vuln")
	l.writeFile(t, "policy.yaml", vulnerabilityPolicy(true))
	l.generateSBOM(t, "--go-mod", "go.mod", "--go-sum", "go.sum")
	return l
}

func TestFailureInjection_OSVOutageFailsClosed(t *testing.T) {
	l := vulnLab(t)
	l.Env["WARDEN_OSV_URL"] = failingServer(t, http.StatusInternalServerError).URL
	failClosed(t, l)
}

func TestFailureInjection_OSVHangIsBoundedAndFailsClosed(t *testing.T) {
	l := vulnLab(t)
	l.Env["WARDEN_OSV_URL"] = hangingServer(t).URL

	start := time.Now()
	failClosed(t, l, "--timeout", "3s")
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Errorf("took %s to give up, want it bounded near --timeout 3s", elapsed)
	}
}

func TestFailureInjection_MalformedOSVResponsesFailClosed(t *testing.T) {
	cases := map[string]string{
		"invalid JSON":               "<html>rate limited</html>",
		"fewer results than queries": `{"results":[]}`,
		"results of the wrong type":  `{"results":"nope"}`,
		"a bare null":                `null`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			l := vulnLab(t)
			l.Env["WARDEN_OSV_URL"] = bodyServer(t, body).URL
			failClosed(t, l)
		})
	}
}

// OSV answers the query with a vulnerability ID, then has no record of it.
func TestFailureInjection_DanglingVulnerabilityReferenceFailsClosed(t *testing.T) {
	l := vulnLab(t)
	l.OSV.AddVuln(goVulnPURL, testVulnID, criticalCVSS, testCVE)
	l.OSV.DropRecord(testVulnID)
	failClosed(t, l)
}

// Garbage from the license source means those components weren't checked.
func TestFailureInjection_MalformedDepsDevResponseIsAGap(t *testing.T) {
	l := newLab(t)
	l.useProject(t, "go-vuln")
	l.writeFile(t, "policy.yaml", licensePolicy)
	l.generateSBOM(t, "--go-mod", "go.mod", "--go-sum", "go.sum")
	l.Env["WARDEN_DEPSDEV_URL"] = bodyServer(t, "<html>not json</html>").URL

	gate := l.gate(t, "policy.yaml")
	if gate.Passed || countRule(gate.Violations, "coverage") != 2 {
		t.Errorf("got %+v, want both dependencies reported as unchecked", gate)
	}
}
