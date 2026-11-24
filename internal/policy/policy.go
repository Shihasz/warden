// Package policy defines warden's policy file schema and evaluates it
// against vulnerability, license, and provenance findings to produce a
// pass/fail gate decision.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/Shihasz/warden/internal/license/classify"
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

var validSeverities = []string{"low", "medium", "high", "critical"}

// Load reads, strictly parses, and validates a policy file.
//
// Strictness is deliberate. A policy is configuration for a security gate,
// and the failure mode of a typo is a rule that silently never fires while
// the pipeline stays green. So unknown keys are errors, unrecognized
// values are errors, and settings that would have no effect are errors.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("policy file %s is empty", path)
		}
		return nil, fmt.Errorf("parse policy file: %w", err)
	}

	if p.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version %d (only version 1 is supported)", p.Version)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// validate rejects settings that are unrecognized, or that would have no
// effect, and reports every problem at once.
func (p *Policy) validate() error {
	var problems []string

	vp := p.Vulnerabilities
	if vp.DenySeverity != "" && !slices.Contains(validSeverities, vp.DenySeverity) {
		problems = append(problems, fmt.Sprintf("vulnerabilities.denySeverity %q is not one of %s (lowercase)", vp.DenySeverity, strings.Join(validSeverities, ", ")))
	}
	unscoredValid := vp.UnscoredSeverity == "deny" || vp.UnscoredSeverity == "ignore"
	if vp.UnscoredSeverity != "" && !unscoredValid {
		problems = append(problems, fmt.Sprintf("vulnerabilities.unscoredSeverity must be \"deny\" or \"ignore\", got %q", vp.UnscoredSeverity))
	}
	if vp.DenySeverity == "" {
		if vp.RequireKnownExploit {
			problems = append(problems, "vulnerabilities.requireKnownExploit has no effect without vulnerabilities.denySeverity, which is what enables the rule")
		}
		if unscoredValid {
			problems = append(problems, "vulnerabilities.unscoredSeverity has no effect without vulnerabilities.denySeverity, which is what enables the rule")
		}
	}

	for _, c := range p.Licenses.DenyCategories {
		if !classify.Valid(classify.Category(c)) {
			problems = append(problems, fmt.Sprintf("licenses.denyCategories contains %q, which is not one of %s", c, classify.List()))
		}
	}

	pp := p.Provenance
	if pp.MinLevel < 0 || pp.MinLevel > 2 {
		problems = append(problems, fmt.Sprintf("provenance.minLevel %d is out of range (0 to 2)", pp.MinLevel))
	}
	if !pp.Required && (pp.MinLevel != 0 || pp.ExpectedRepository != "" || pp.ExpectedRef != "") {
		problems = append(problems, "provenance.minLevel, expectedRepository, and expectedRef are ignored unless provenance.required is true")
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("invalid policy:\n  - %s", strings.Join(problems, "\n  - "))
}

// EnforcesNothing reports whether the policy enables no rule at all, so
// that every run passes by construction. The caller should say so rather
// than let it look like a configured gate.
func (p *Policy) EnforcesNothing() bool {
	return p.Vulnerabilities.DenySeverity == "" &&
		len(p.Licenses.DenyCategories) == 0 &&
		!p.Provenance.Required
}
