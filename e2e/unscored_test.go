//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
)

const cvss4Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

func unscoredPolicy(unscored string, requireKnownExploit bool) string {
	policy := fmt.Sprintf("version: 1\n\nvulnerabilities:\n  denySeverity: critical\n  requireKnownExploit: %t\n", requireKnownExploit)
	if unscored != "" {
		policy += "  unscoredSeverity: " + unscored + "\n"
	}
	return policy
}

// A vulnerability confirmed as exploited in the wild must not pass merely
// because it has no usable CVSS v3 score (CVSS v4 only, no score at all, or
// a malformed database label), unless the policy says to ignore those.
func TestVulnerabilityGate_UnscoredFindings(t *testing.T) {
	v4 := []osvSeverity{{Type: "CVSS_V4", Score: cvss4Vector}}
	aliases := []string{testCVE}

	cases := []struct {
		name        string
		record      osvVuln
		exploited   bool
		policy      string
		wantBlocked bool
		wantInMsg   string
	}{
		{"CVSS v4 only, exploited", osvVuln{ID: testVulnID, Aliases: aliases, Severity: v4}, true, unscoredPolicy("", true), true, "unscored"},
		{"CVSS v4 only, exploited, unscored ignored", osvVuln{ID: testVulnID, Aliases: aliases, Severity: v4}, true, unscoredPolicy("ignore", true), false, ""},
		{"CVSS v4 only, not exploited", osvVuln{ID: testVulnID, Aliases: aliases, Severity: v4}, false, unscoredPolicy("", true), false, ""},
		{"no severity at all, exploited", osvVuln{ID: testVulnID, Aliases: aliases}, true, unscoredPolicy("", true), true, "unscored"},
		{"no severity, exploit not required", osvVuln{ID: testVulnID, Aliases: aliases}, false, unscoredPolicy("", false), true, "unscored"},
		{
			"advisory label CRITICAL on a v4-only record",
			osvVuln{ID: testVulnID, Aliases: aliases, Severity: v4, DatabaseSpecific: map[string]any{"severity": "CRITICAL"}},
			true, unscoredPolicy("", true), true, "advisory-label",
		},
		{
			"advisory label LOW is below the threshold",
			osvVuln{ID: testVulnID, Aliases: aliases, Severity: v4, DatabaseSpecific: map[string]any{"severity": "LOW"}},
			true, unscoredPolicy("", true), false, "",
		},
		{
			"malformed database_specific is treated as unscored",
			osvVuln{ID: testVulnID, Aliases: aliases, DatabaseSpecific: map[string]any{"severity": 5}},
			true, unscoredPolicy("", true), true, "unscored",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := newLab(t)
			l.useProject(t, "go-vuln")
			l.writeFile(t, "policy.yaml", tc.policy)
			l.OSV.AddRecord(goVulnPURL, tc.record)
			if tc.exploited {
				l.KEV.SetExploited(testCVE)
			}
			l.generateSBOM(t, "--go-mod", "go.mod", "--go-sum", "go.sum")

			gate := l.gate(t, "policy.yaml")
			if gate.Passed == tc.wantBlocked {
				t.Fatalf("passed = %v, want blocked = %v; violations: %+v", gate.Passed, tc.wantBlocked, gate.Violations)
			}
			if tc.wantBlocked {
				if len(gate.Violations) != 1 {
					t.Fatalf("got %d violations, want exactly 1: %+v", len(gate.Violations), gate.Violations)
				}
				if !strings.Contains(gate.Violations[0].Message, tc.wantInMsg) {
					t.Errorf("violation message %q does not contain %q", gate.Violations[0].Message, tc.wantInMsg)
				}
			}
		})
	}
}

// A policy with an unrecognized value must stop the command with an error,
// never quietly pass and never quietly change meaning.
func TestPolicyCheck_RejectsInvalidUnscoredSeverity(t *testing.T) {
	l := newLab(t)
	l.useProject(t, "go-vuln")
	l.writeFile(t, "policy.yaml", unscoredPolicy("maybe", true))
	l.generateSBOM(t, "--go-mod", "go.mod", "--go-sum", "go.sum")

	res := l.run(t, "policy", "check", "--sbom", "sbom.json", "--policy", "policy.yaml")
	res.requireExit(t, 1)
	if !strings.Contains(res.stderr, "unscoredSeverity") {
		t.Errorf("stderr = %q, want it to name the invalid setting", res.stderr)
	}
	if strings.Contains(res.stdout, `"passed": true`) {
		t.Errorf("an invalid policy produced a passing result: %s", res.stdout)
	}
}
