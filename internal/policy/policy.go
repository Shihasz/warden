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
// denial. A finding is denied when its CVSS base severity is at least
// DenySeverity, and — if RequireKnownExploit is true — it is also
// flagged as actively exploited by the CISA KEV catalog. A finding whose
// severity can't be determined (no CVSS data, or an unsupported/
// unparseable vector) is never denied by this rule; "we don't know" is
// deliberately not treated the same as "this is bad".
type VulnerabilityPolicy struct {
	// DenySeverity is the minimum CVSS severity this rule considers at
	// all: "low", "medium", "high", or "critical". Empty disables the
	// rule entirely.
	DenySeverity string `yaml:"denySeverity"`
	// RequireKnownExploit, if true, only denies a finding that is both
	// at or above DenySeverity AND flagged known-exploited by KEV. If
	// false, meeting the severity threshold alone is sufficient.
	RequireKnownExploit bool `yaml:"requireKnownExploit"`
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
//	1 = signature, artifact digest, and build identity all verified
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

	return &p, nil
}
