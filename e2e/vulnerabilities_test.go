//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

const (
	// The two vectors the cvss package's unit tests verified by hand.
	criticalCVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" // base score 9.8
	mediumCVSS   = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" // base score 6.5

	testCVE    = "CVE-2099-0001"
	testVulnID = "GHSA-e2e0-0001-0001"

	goVulnPURL = "pkg:golang/github.com/example/vulnlib@v1.0.0"
)

// A critical, known-exploited vulnerability must block the gate in every
// ecosystem, which exercises purl construction (scoped npm names, PEP 503
// normalization), the OSV query, the CVSS scoring, the KEV match, and the
// policy rule through the real binary.
func TestVulnerabilityGate_EachEcosystem(t *testing.T) {
	cases := []struct {
		name     string
		project  string
		sbomArgs []string
		purl     string
		subject  string // how the violation names the component
	}{
		{
			name:     "go",
			project:  "go-vuln",
			sbomArgs: []string{"--go-mod", "go.mod", "--go-sum", "go.sum"},
			purl:     goVulnPURL,
			subject:  "github.com/example/vulnlib@v1.0.0",
		},
		{
			name:     "npm",
			project:  "npm-vuln",
			sbomArgs: []string{"--npm-lock", "package-lock.json"},
			purl:     "pkg:npm/vulnpkg@1.0.0",
			subject:  "vulnpkg@1.0.0",
		},
		{
			name:     "npm scoped package",
			project:  "npm-vuln",
			sbomArgs: []string{"--npm-lock", "package-lock.json"},
			purl:     "pkg:npm/%40scope/vulnscoped@2.0.0",
			subject:  "@scope/vulnscoped@2.0.0",
		},
		{
			name:     "pip with a name that needs normalizing",
			project:  "pip-vuln",
			sbomArgs: []string{"--pip-requirements", "requirements.txt"},
			purl:     "pkg:pypi/flask-vuln@2.0.0",
			subject:  "flask-vuln@2.0.0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := newLab(t)
			l.useProject(t, tc.project)
			// The repository's own policy: critical AND exploited.
			l.copyRepoFile(t, "../warden-policy-no-provenance.yaml", "policy.yaml")
			l.OSV.AddVuln(tc.purl, testVulnID, criticalCVSS, testCVE)
			l.KEV.SetExploited(testCVE)

			l.generateSBOM(t, tc.sbomArgs...)

			gate := l.gate(t, "policy.yaml")
			if gate.Passed {
				t.Fatalf("a critical, known-exploited vulnerability passed the gate")
			}
			if len(gate.Violations) != 1 {
				t.Fatalf("got %d violations, want exactly 1: %+v", len(gate.Violations), gate.Violations)
			}
			v := gate.Violations[0]
			if v.Rule != "vulnerability" || v.Subject != tc.subject {
				t.Errorf("violation = %+v, want a vulnerability violation for %s", v, tc.subject)
			}
			for _, want := range []string{testVulnID, "severity=critical", "knownExploited=true"} {
				if !strings.Contains(v.Message, want) {
					t.Errorf("violation message %q does not contain %q", v.Message, want)
				}
			}

			// The scan reports the same finding, flagged as exploited.
			scan := l.run(t, "scan", "--sbom", "sbom.json")
			scan.requireExit(t, 0)
			var out struct {
				Findings []struct {
					Vulnerabilities []struct {
						ID             string `json:"id"`
						KnownExploited bool   `json:"knownExploited"`
					} `json:"vulnerabilities"`
				} `json:"findings"`
			}
			scan.decode(t, &out)
			if len(out.Findings) != 1 || len(out.Findings[0].Vulnerabilities) != 1 {
				t.Fatalf("scan findings = %+v, want exactly one vulnerability", out.Findings)
			}
			got := out.Findings[0].Vulnerabilities[0]
			if got.ID != testVulnID || !got.KnownExploited {
				t.Errorf("scan finding = %+v, want %s flagged knownExploited", got, testVulnID)
			}
		})
	}
}

// The rule is "at or above the severity threshold, and (if configured)
// also known-exploited". Every combination is exercised.
func TestVulnerabilityGate_SeverityAndExploitMatrix(t *testing.T) {
	cases := []struct {
		name                string
		cvss                string
		exploited           bool
		requireKnownExploit bool
		wantBlocked         bool
	}{
		{"critical and exploited, exploit required", criticalCVSS, true, true, true},
		{"critical not exploited, exploit required", criticalCVSS, false, true, false},
		{"critical not exploited, exploit not required", criticalCVSS, false, false, true},
		{"critical and exploited, exploit not required", criticalCVSS, true, false, true},
		{"medium and exploited, exploit required", mediumCVSS, true, true, false},
		{"medium not exploited, exploit not required", mediumCVSS, false, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := newLab(t)
			l.useProject(t, "go-vuln")
			l.writeFile(t, "policy.yaml", vulnerabilityPolicy(tc.requireKnownExploit))
			l.OSV.AddVuln(goVulnPURL, testVulnID, tc.cvss, testCVE)
			if tc.exploited {
				l.KEV.SetExploited(testCVE)
			}

			l.generateSBOM(t, "--go-mod", "go.mod", "--go-sum", "go.sum")

			gate := l.gate(t, "policy.yaml")
			if gate.Passed == tc.wantBlocked {
				t.Fatalf("passed = %v, want blocked = %v; violations: %+v", gate.Passed, tc.wantBlocked, gate.Violations)
			}
			if tc.wantBlocked && len(gate.Violations) != 1 {
				t.Errorf("got %d violations, want exactly 1: %+v", len(gate.Violations), gate.Violations)
			}
		})
	}
}

// KEV lists CVE IDs, but OSV records name them in different places: GitHub
// advisories list the CVE as an alias, while records imported from the NVD
// are identified by the CVE itself and list no aliases at all.
func TestVulnerabilityGate_KEVMatchesWhereverTheCVEAppears(t *testing.T) {
	critical := []osvSeverity{{Type: "CVSS_V3", Score: criticalCVSS}}

	cases := []struct {
		name        string
		record      osvVuln
		exploited   []string
		wantBlocked bool
	}{
		{
			name:        "CVE listed as the only alias",
			record:      osvVuln{ID: testVulnID, Aliases: []string{testCVE}, Severity: critical},
			exploited:   []string{testCVE},
			wantBlocked: true,
		},
		{
			name:        "record identified by the CVE itself, no aliases",
			record:      osvVuln{ID: testCVE, Severity: critical},
			exploited:   []string{testCVE},
			wantBlocked: true,
		},
		{
			name:        "CVE among several aliases",
			record:      osvVuln{ID: testVulnID, Aliases: []string{"GHSA-other-0000-0000", testCVE}, Severity: critical},
			exploited:   []string{testCVE},
			wantBlocked: true,
		},
		{
			name:        "a different CVE is the exploited one",
			record:      osvVuln{ID: testVulnID, Aliases: []string{testCVE}, Severity: critical},
			exploited:   []string{"CVE-2099-9999"},
			wantBlocked: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := newLab(t)
			l.useProject(t, "go-vuln")
			l.writeFile(t, "policy.yaml", vulnerabilityPolicy(true))
			l.OSV.AddRecord(goVulnPURL, tc.record)
			l.KEV.SetExploited(tc.exploited...)

			l.generateSBOM(t, "--go-mod", "go.mod", "--go-sum", "go.sum")

			gate := l.gate(t, "policy.yaml")
			if gate.Passed == tc.wantBlocked {
				t.Fatalf("passed = %v, want blocked = %v; violations: %+v", gate.Passed, tc.wantBlocked, gate.Violations)
			}
		})
	}
}
