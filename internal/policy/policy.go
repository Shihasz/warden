// Package policy defines warden's policy file schema and evaluates it
// against vulnerability, license, and provenance findings to produce a
// pass/fail gate decision.
package policy

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

// Policy is warden's policy file schema (version 1).
type Policy struct {
	Version         int                 `yaml:"version"`
	Vulnerabilities VulnerabilityPolicy `yaml:"vulnerabilities"`
	Licenses        LicensePolicy       `yaml:"licenses"`
	Provenance      ProvenancePolicy    `yaml:"provenance"`
}

// VulnerabilityPolicy controls which vulnerability findings cause a
// denial. A finding is denied when its severity is at least DenySeverity
// and, if RequireKnownExploit is true, it is also listed as actively
// exploited by CISA's KEV catalog.
//
// A finding's severity comes from its CVSS v3 vector if it has a usable
// one, otherwise from the advisory database's own severity label. A
// finding with neither is "unscored", and UnscoredSeverity decides what
// happens to it.
type VulnerabilityPolicy struct {
	// DenySeverity is the minimum severity this rule considers at all:
	// "low", "medium", "high", or "critical". Empty disables the rule.
	DenySeverity string `yaml:"denySeverity"`
	// RequireKnownExploit, if true, only denies a finding that is both at
	// or above DenySeverity AND flagged known-exploited by KEV.
	RequireKnownExploit bool `yaml:"requireKnownExploit"`
	// UnscoredSeverity is "deny" (the default when empty) or "ignore".
	// "deny" treats an unscored finding as meeting DenySeverity, assuming
	// the worst case, so a vulnerability confirmed as exploited in the
	// wild can't pass merely because nobody scored it. "ignore" never
	// denies an unscored finding.
	UnscoredSeverity string `yaml:"unscoredSeverity"`
}

// LicensePolicy denies any component whose classified license category
// (see internal/license/classify) is listed in DenyCategories.
type LicensePolicy struct {
	DenyCategories []string `yaml:"denyCategories"`
}

// ProvenancePolicy controls what a build's provenance attestation must
// satisfy.
//
// MinLevel uses warden's own simplified 0-2 scale — not an official SLSA
// build level, which also certifies properties (build isolation,
// hermeticity) warden does not assess:
//
//	0 = no valid attestation (missing, unsigned, or fails verification)
//	1 = signature and artifact digest verified, and the signing key bound
//	    to a GitHub-signed build identity (see Statement.VerifyBinding)
//	2 = level 1, AND the build ran on a GitHub-hosted (not self-hosted) runner
type ProvenancePolicy struct {
	Required           bool   `yaml:"required"`
	MinLevel           int    `yaml:"minLevel"`
	ExpectedRepository string `yaml:"expectedRepository"`
	ExpectedRef        string `yaml:"expectedRef"`
}

// Load reads and parses a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy file: %w", err)
	}

	if p.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version %d (only version 1 is supported)", p.Version)
	}

	switch p.Vulnerabilities.UnscoredSeverity {
	case "", "deny", "ignore":
	default:
		return nil, fmt.Errorf("vulnerabilities.unscoredSeverity must be \"deny\" or \"ignore\", got %q", p.Vulnerabilities.UnscoredSeverity)
	}

	return &p, nil
}
