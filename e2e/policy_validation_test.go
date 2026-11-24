//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// Each of these is a plausible slip in a policy file. All of them used to
// be accepted and silently left the gate with a rule switched off. Every
// one must now stop the command with an error naming the mistake, and
// must never produce a passing result.
func TestPolicyCheck_MistakesFailLoudly(t *testing.T) {
	cases := []struct {
		name   string
		policy string
		want   string
	}{
		{"misspelled key", "version: 1\nvulnerabilities:\n  denySeverty: critical\n  requireKnownExploit: true\n", "denySeverty"},
		{"unknown severity", "version: 1\nvulnerabilities:\n  denySeverity: criticl\n", "criticl"},
		{"misspelled license category", "version: 1\nlicenses:\n  denyCategories: [copyleftt]\n", "copyleftt"},
		{"out-of-range provenance level", "version: 1\nprovenance:\n  required: true\n  minLevel: 5\n", "minLevel"},
		{"setting with no effect", "version: 1\nvulnerabilities:\n  requireKnownExploit: true\n", "requireKnownExploit"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := newLab(t)
			l.useProject(t, "go-vuln")
			l.writeFile(t, "policy.yaml", tc.policy)
			l.generateSBOM(t, "--go-mod", "go.mod", "--go-sum", "go.sum")

			res := l.run(t, "policy", "check", "--sbom", "sbom.json", "--policy", "policy.yaml")
			res.requireExit(t, 1)
			if !strings.Contains(res.stderr, tc.want) {
				t.Errorf("stderr = %q, want it to name %q", res.stderr, tc.want)
			}
			if strings.Contains(res.stdout, `"passed": true`) {
				t.Errorf("an invalid policy produced a passing result:\n%s", res.stdout)
			}
		})
	}
}

func TestPolicyCheck_EmptyPolicyWarnsThatNothingIsEnforced(t *testing.T) {
	l := newLab(t)
	l.useProject(t, "go-vuln")
	l.writeFile(t, "policy.yaml", "version: 1\n")
	l.generateSBOM(t, "--go-mod", "go.mod", "--go-sum", "go.sum")

	res := l.run(t, "policy", "check", "--sbom", "sbom.json", "--policy", "policy.yaml")
	res.requireExit(t, 0)
	if !strings.Contains(res.stderr, "enables no rules") {
		t.Errorf("stderr = %q, want a warning that nothing is enforced", res.stderr)
	}
}

func TestLicensesCheck_UnknownDenyCategoryFailsLoudly(t *testing.T) {
	l := newLab(t)
	l.useProject(t, "go-vuln")
	l.generateSBOM(t, "--go-mod", "go.mod", "--go-sum", "go.sum")

	res := l.run(t, "licenses", "check", "--sbom", "sbom.json", "--deny-category", "copyleftt")
	res.requireExit(t, 1)
	if !strings.Contains(res.stderr, "copyleftt") {
		t.Errorf("stderr = %q, want it to name the bad category", res.stderr)
	}
}
