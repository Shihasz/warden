package policy

import (
	"fmt"
	"strings"

	"github.com/Shihasz/warden/internal/license/classify"
	"github.com/Shihasz/warden/internal/license/depsdev"
	"github.com/Shihasz/warden/internal/provenance/attest"
	"github.com/Shihasz/warden/internal/vuln"
	"github.com/Shihasz/warden/internal/vuln/cvss"
	"github.com/Shihasz/warden/internal/vuln/osv"
)

// Violation describes a single policy rule failure.
type Violation struct {
	Rule    string `json:"rule"`    // "vulnerability", "license", or "provenance"
	Subject string `json:"subject"` // e.g. "component-name@1.2.3", or "provenance"
	Message string `json:"message"`
}

// Result is the outcome of evaluating a Policy.
type Result struct {
	Violations []Violation `json:"violations"`
}

// Passed reports whether evaluation found zero violations.
func (r Result) Passed() bool {
	return len(r.Violations) == 0
}

// ProvenanceInput is what the caller supplies after independently
// attempting to verify a build's attestation. Verified is false if
// verification failed for any reason (missing file, invalid signature,
// digest mismatch, and so on) — in which case Statement is ignored, even
// if non-nil.
type ProvenanceInput struct {
	Verified  bool
	Statement *attest.Statement
}

var severityRank = map[string]int{"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Where a vulnerability's severity came from.
const (
	sourceCVSS3 = "cvss-v3"
	sourceLabel = "advisory-label"
	sourceNone  = "unscored"
)

// Evaluate checks vulnFindings, licenseResults, and prov against p and
// returns every violation found. It deliberately does not stop at the
// first violation — a complete report is more useful to someone fixing
// their pipeline than a single failure that hides the rest.
func Evaluate(p *Policy, vulnFindings []vuln.ComponentFinding, licenseResults []depsdev.LicenseResult, prov ProvenanceInput) Result {
	var violations []Violation
	violations = append(violations, evaluateVulnerabilities(p.Vulnerabilities, vulnFindings)...)
	violations = append(violations, evaluateLicenses(p.Licenses, licenseResults)...)
	violations = append(violations, evaluateProvenance(p.Provenance, prov)...)
	return Result{Violations: violations}
}

func evaluateVulnerabilities(vp VulnerabilityPolicy, findings []vuln.ComponentFinding) []Violation {
	if vp.DenySeverity == "" {
		return nil
	}
	threshold, ok := severityRank[vp.DenySeverity]
	if !ok {
		// An invalid config value disables the rule rather than denying
		// everything or panicking.
		return nil
	}
	denyUnscored := vp.UnscoredSeverity != "ignore" // deny is the default

	var violations []Violation
	for _, f := range findings {
		for _, v := range f.Vulnerabilities {
			sev, source := severityOf(v.Vulnerability)

			var description string
			if source == sourceNone {
				if !denyUnscored {
					continue
				}
				// Worst-case assumption: an unscored finding is treated
				// as meeting the threshold.
				description = fmt.Sprintf("severity=unscored (treated as meeting %s, per unscoredSeverity)", vp.DenySeverity)
			} else {
				if severityRank[sev] < threshold {
					continue
				}
				description = fmt.Sprintf("severity=%s (%s)", sev, source)
			}

			if vp.RequireKnownExploit && !v.KnownExploited {
				continue
			}
			violations = append(violations, Violation{
				Rule:    "vulnerability",
				Subject: fmt.Sprintf("%s@%s", f.Component.Name, f.Component.Version),
				Message: fmt.Sprintf("%s: %s knownExploited=%v", v.ID, description, v.KnownExploited),
			})
		}
	}
	return violations
}

// severityOf resolves a vulnerability's severity and where it came from:
// its CVSS v3 vector if one scores, otherwise the advisory database's own
// label, otherwise sourceNone. CVSS wins because warden computes it
// itself from the vector; a database label is a weaker, secondhand claim.
func severityOf(v osv.Vulnerability) (severity, source string) {
	for _, s := range v.Severity {
		if s.Type != "CVSS_V3" {
			continue
		}
		m, err := cvss.ParseVector(s.Score)
		if err != nil {
			continue
		}
		score, err := cvss.BaseScore(m)
		if err != nil {
			continue
		}
		return cvss.Severity(score), sourceCVSS3
	}
	if label := labelSeverity(v.DatabaseSeverity()); label != "" {
		return label, sourceLabel
	}
	return "", sourceNone
}

// labelSeverity maps an advisory database's qualitative label onto warden's
// severity names. GitHub's advisories say "MODERATE" where CVSS says medium.
func labelSeverity(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MODERATE", "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	}
	return ""
}

func evaluateLicenses(lp LicensePolicy, results []depsdev.LicenseResult) []Violation {
	if len(lp.DenyCategories) == 0 {
		return nil
	}
	deny := make(map[classify.Category]bool, len(lp.DenyCategories))
	for _, c := range lp.DenyCategories {
		deny[classify.Category(c)] = true
	}

	var violations []Violation
	for _, r := range results {
		cat := classify.Classify(r.Licenses)
		if !deny[cat] {
			continue
		}
		violations = append(violations, Violation{
			Rule:    "license",
			Subject: fmt.Sprintf("%s@%s", r.Component.Name, r.Component.Version),
			Message: fmt.Sprintf("license category %q is denied (licenses: %v)", cat, r.Licenses),
		})
	}
	return violations
}

func evaluateProvenance(pp ProvenancePolicy, prov ProvenanceInput) []Violation {
	if !pp.Required {
		return nil
	}
	if !prov.Verified || prov.Statement == nil {
		return []Violation{{Rule: "provenance", Subject: "provenance", Message: "no verified provenance attestation found"}}
	}

	if level := provenanceLevel(prov.Statement); level < pp.MinLevel {
		return []Violation{{Rule: "provenance", Subject: "provenance", Message: fmt.Sprintf("provenance level %d is below required minimum %d", level, pp.MinLevel)}}
	}

	if pp.ExpectedRepository != "" || pp.ExpectedRef != "" {
		exp := attest.ExpectedIdentity{Repository: pp.ExpectedRepository, Ref: pp.ExpectedRef}
		if err := prov.Statement.CheckIdentity(exp); err != nil {
			return []Violation{{Rule: "provenance", Subject: "provenance", Message: err.Error()}}
		}
	}

	return nil
}

// provenanceLevel computes warden's own simplified 0-2 provenance level
// (see ProvenancePolicy's doc comment) from a verified statement.
func provenanceLevel(stmt *attest.Statement) int {
	if stmt.Predicate.BuildDefinition.InternalParameters["runnerEnvironment"] == "github-hosted" {
		return 2
	}
	return 1
}
