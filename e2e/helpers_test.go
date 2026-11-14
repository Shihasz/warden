//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"testing"
)

// writeFile creates a file in the lab's project directory.
func (l *lab) writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(l.path(name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// generateSBOM runs `warden sbom generate` over the given dependency-file
// flags, writing sbom.json into the lab.
func (l *lab) generateSBOM(t *testing.T, args ...string) {
	t.Helper()
	full := append([]string{"sbom", "generate"}, args...)
	full = append(full, "--name", "e2e", "-o", "sbom.json")
	l.run(t, full...).requireExit(t, 0)
}

type violation struct {
	Rule    string `json:"rule"`
	Subject string `json:"subject"`
	Message string `json:"message"`
}

type gateResult struct {
	Passed     bool        `json:"passed"`
	Violations []violation `json:"violations"`
}

// gate runs `warden policy check` over the lab's sbom.json. It also checks
// that the exit code agrees with the verdict: a gate that prints "passed"
// but exits non-zero (or the reverse) would break every pipeline using it.
func (l *lab) gate(t *testing.T, policyFile string, extra ...string) gateResult {
	t.Helper()
	args := append([]string{"policy", "check", "--sbom", "sbom.json", "--policy", policyFile}, extra...)
	res := l.run(t, args...)

	var out gateResult
	res.decode(t, &out)

	wantExit := 1
	if out.Passed {
		wantExit = 0
	}
	res.requireExit(t, wantExit)
	return out
}

// vulnerabilityPolicy is a policy with only the vulnerability rule:
// critical findings are denied, and with requireKnownExploit they must
// also be listed as exploited by CISA's KEV catalog.
func vulnerabilityPolicy(requireKnownExploit bool) string {
	return fmt.Sprintf(`version: 1

vulnerabilities:
  denySeverity: critical
  requireKnownExploit: %t
`, requireKnownExploit)
}

// AddRecord registers a complete OSV record against a package, for
// scenarios that need control over fields AddVuln doesn't expose.
func (m *mockOSV) AddRecord(purl string, v osvVuln) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vulns[v.ID] = v
	m.byPURL[purl] = append(m.byPURL[purl], v.ID)
}
