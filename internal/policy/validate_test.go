package policy

import (
	"strings"
	"testing"
)

func TestLoad_RejectsMistakes(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string // must appear in the error, so a case can't fail for the wrong reason
	}{
		{"misspelled section", "version: 1\nvulnerabilites:\n  denySeverity: critical\n", "vulnerabilites"},
		{"misspelled key", "version: 1\nvulnerabilities:\n  denySeverty: critical\n", "denySeverty"},
		{"key at the wrong indentation", "version: 1\nvulnerabilities:\ndenySeverity: critical\n", "denySeverity"},
		{"unknown severity", "version: 1\nvulnerabilities:\n  denySeverity: criticl\n", "criticl"},
		{"severity not lowercase", "version: 1\nvulnerabilities:\n  denySeverity: CRITICAL\n", "CRITICAL"},
		{"severity none", "version: 1\nvulnerabilities:\n  denySeverity: none\n", "none"},
		{"misspelled category", "version: 1\nlicenses:\n  denyCategories:\n    - copyleftt\n", "copyleftt"},
		{"category wrong case", "version: 1\nlicenses:\n  denyCategories:\n    - Copyleft\n", "Copyleft"},
		{"minLevel too high", "version: 1\nprovenance:\n  required: true\n  minLevel: 3\n", "minLevel"},
		{"minLevel negative", "version: 1\nprovenance:\n  required: true\n  minLevel: -1\n", "minLevel"},
		{"requireKnownExploit without denySeverity", "version: 1\nvulnerabilities:\n  requireKnownExploit: true\n", "requireKnownExploit"},
		{"unscoredSeverity without denySeverity", "version: 1\nvulnerabilities:\n  unscoredSeverity: deny\n", "unscoredSeverity"},
		{"expectedRepository without required", "version: 1\nprovenance:\n  expectedRepository: https://github.com/a/b\n", "provenance.required"},
		{"minLevel without required", "version: 1\nprovenance:\n  minLevel: 2\n", "provenance.required"},
		{"empty file", "", "empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writePolicyFixture(t, tc.content))
			if err == nil {
				t.Fatalf("Load() accepted a policy that should be rejected:\n%s", tc.content)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q (it may be failing for the wrong reason)", err.Error(), tc.want)
			}
		})
	}
}

func TestLoad_ReportsEveryProblemAtOnce(t *testing.T) {
	content := "version: 1\nvulnerabilities:\n  denySeverity: criticl\nlicenses:\n  denyCategories: [copyleftt]\nprovenance:\n  required: true\n  minLevel: 9\n"
	_, err := Load(writePolicyFixture(t, content))
	if err == nil {
		t.Fatal("Load() accepted an invalid policy")
	}
	for _, want := range []string{"criticl", "copyleftt", "minLevel"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to report %q too", err.Error(), want)
		}
	}
}

func TestLoad_AcceptsValidPolicies(t *testing.T) {
	cases := map[string]string{
		"vulnerabilities only":                   "version: 1\nvulnerabilities:\n  denySeverity: high\n",
		"vulnerabilities with every setting":     "version: 1\nvulnerabilities:\n  denySeverity: low\n  requireKnownExploit: true\n  unscoredSeverity: ignore\n",
		"every license category":                 "version: 1\nlicenses:\n  denyCategories: [permissive, weak-copyleft, copyleft, unknown]\n",
		"provenance required with every setting": "version: 1\nprovenance:\n  required: true\n  minLevel: 2\n  expectedRepository: https://github.com/a/b\n  expectedRef: refs/heads/main\n",
		"provenance explicitly not required":     "version: 1\nprovenance:\n  required: false\n",
		"no rules at all":                        "version: 1\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writePolicyFixture(t, content)); err != nil {
				t.Errorf("Load() error = %v, want it accepted", err)
			}
		})
	}
}

func TestPolicy_EnforcesNothing(t *testing.T) {
	cases := map[string]bool{
		"version: 1\n": true,
		"version: 1\nprovenance:\n  required: false\n":               true,
		"version: 1\nvulnerabilities:\n  denySeverity: high\n":       false,
		"version: 1\nlicenses:\n  denyCategories: [copyleft]\n":      false,
		"version: 1\nprovenance:\n  required: true\n  minLevel: 1\n": false,
	}
	for content, want := range cases {
		p, err := Load(writePolicyFixture(t, content))
		if err != nil {
			t.Fatalf("Load(%q) error = %v", content, err)
		}
		if got := p.EnforcesNothing(); got != want {
			t.Errorf("EnforcesNothing() for %q = %v, want %v", content, got, want)
		}
	}
}
