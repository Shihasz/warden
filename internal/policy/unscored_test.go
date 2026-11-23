package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Shihasz/warden/internal/sbom"
	"github.com/Shihasz/warden/internal/vuln"
	"github.com/Shihasz/warden/internal/vuln/osv"
)

// unscoredFinding is a vulnerability with no CVSS data at all. A non-empty
// databaseSpecific attaches the advisory database's raw extra data.
func unscoredFinding(exploited bool, databaseSpecific string) vuln.ComponentFinding {
	v := osv.Vulnerability{ID: "OSV-UNSCORED-1"}
	if databaseSpecific != "" {
		v.DatabaseSpecific = json.RawMessage(databaseSpecific)
	}
	return vuln.ComponentFinding{
		Component:       sbom.Component{Name: "pkg", Version: "1.0.0"},
		Vulnerabilities: []vuln.VulnResult{{Vulnerability: v, KnownExploited: exploited}},
	}
}

func TestEvaluateVulnerabilities_Unscored(t *testing.T) {
	cases := []struct {
		name        string
		policy      VulnerabilityPolicy
		exploited   bool
		wantDenied  bool
		wantMessage string
	}{
		{"exploited, denied by default", VulnerabilityPolicy{DenySeverity: "critical", RequireKnownExploit: true}, true, true, "unscored"},
		{"not exploited, exploit required", VulnerabilityPolicy{DenySeverity: "critical", RequireKnownExploit: true}, false, false, ""},
		{"not exploited, exploit not required, denied by default", VulnerabilityPolicy{DenySeverity: "critical"}, false, true, "unscored"},
		{"explicit deny", VulnerabilityPolicy{DenySeverity: "critical", RequireKnownExploit: true, UnscoredSeverity: "deny"}, true, true, "unscored"},
		{"ignore, exploited", VulnerabilityPolicy{DenySeverity: "critical", RequireKnownExploit: true, UnscoredSeverity: "ignore"}, true, false, ""},
		{"ignore, exploit not required", VulnerabilityPolicy{DenySeverity: "critical", UnscoredSeverity: "ignore"}, false, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evaluateVulnerabilities(tc.policy, []vuln.ComponentFinding{unscoredFinding(tc.exploited, "")})
			if (len(got) == 1) != tc.wantDenied || len(got) > 1 {
				t.Fatalf("got %d violations, wantDenied = %v: %+v", len(got), tc.wantDenied, got)
			}
			if tc.wantDenied && !strings.Contains(got[0].Message, tc.wantMessage) {
				t.Errorf("message %q does not contain %q", got[0].Message, tc.wantMessage)
			}
		})
	}
}

func TestEvaluateVulnerabilities_AdvisoryLabelFallback(t *testing.T) {
	cases := []struct {
		label      string
		deny       string
		wantDenied bool
	}{
		{"CRITICAL", "critical", true},
		{"HIGH", "critical", false},
		{"HIGH", "high", true},
		{"MODERATE", "high", false},
		{"MODERATE", "medium", true},
		{"LOW", "medium", false},
		{"critical", "critical", true}, // case-insensitive
	}
	for _, tc := range cases {
		t.Run(tc.label+" vs "+tc.deny, func(t *testing.T) {
			finding := unscoredFinding(false, `{"severity":"`+tc.label+`"}`)
			got := evaluateVulnerabilities(VulnerabilityPolicy{DenySeverity: tc.deny}, []vuln.ComponentFinding{finding})
			if (len(got) == 1) != tc.wantDenied {
				t.Fatalf("got %+v, wantDenied = %v", got, tc.wantDenied)
			}
			if tc.wantDenied && !strings.Contains(got[0].Message, "advisory-label") {
				t.Errorf("message %q should say the severity came from the advisory label", got[0].Message)
			}
		})
	}
}

// A usable CVSS v3 vector is authoritative: warden computes it itself,
// while a database label is a secondhand claim.
func TestEvaluateVulnerabilities_CVSSBeatsAdvisoryLabel(t *testing.T) {
	finding := findingWith("pkg", mediumVector, false)
	finding.Vulnerabilities[0].DatabaseSpecific = json.RawMessage(`{"severity":"CRITICAL"}`)

	got := evaluateVulnerabilities(VulnerabilityPolicy{DenySeverity: "critical"}, []vuln.ComponentFinding{finding})
	if len(got) != 0 {
		t.Errorf("got %+v, want none: a medium CVSS score must beat a CRITICAL label", got)
	}
}

// Free-form database_specific data that isn't a usable label counts as
// "no label" and so as unscored: denied if exploited, never a crash.
func TestEvaluateVulnerabilities_MalformedLabelIsUnscored(t *testing.T) {
	for _, raw := range []string{`{"severity":5}`, `{"severity":["CRITICAL"]}`, `"CRITICAL"`, `[1,2]`, `null`, `{"severity":"BOGUS"}`} {
		got := evaluateVulnerabilities(
			VulnerabilityPolicy{DenySeverity: "critical", RequireKnownExploit: true},
			[]vuln.ComponentFinding{unscoredFinding(true, raw)},
		)
		if len(got) != 1 || !strings.Contains(got[0].Message, "unscored") {
			t.Errorf("database_specific %s: got %+v, want one violation treated as unscored", raw, got)
		}
	}
}

func TestLoad_UnscoredSeverityValues(t *testing.T) {
	for _, value := range []string{"", "deny", "ignore"} {
		content := "version: 1\n"
		if value != "" {
			content += "vulnerabilities:\n  unscoredSeverity: " + value + "\n"
		}
		if _, err := Load(writePolicyFixture(t, content)); err != nil {
			t.Errorf("Load() with unscoredSeverity %q error = %v, want it accepted", value, err)
		}
	}
	for _, value := range []string{"maybe", "Deny", "true", "warn"} {
		content := "version: 1\nvulnerabilities:\n  unscoredSeverity: " + value + "\n"
		if _, err := Load(writePolicyFixture(t, content)); err == nil {
			t.Errorf("Load() with unscoredSeverity %q should be rejected, got nil error", value)
		}
	}
}
