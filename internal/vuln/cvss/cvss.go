// Package cvss implements CVSS v3.1 (and the identical v3.0 base-metric
// formula) base score calculation from a vector string, per the official
// specification published by FIRST.org.
//
// Only base metrics are implemented — temporal and environmental scoring
// are not — since the base score is what OSV, NVD, and GHSA actually
// publish, and what a dependency policy evaluates against.
//
// CVSS v2 and v4 vectors use different metric sets and formulas entirely
// and are not supported; ParseVector returns an error for either.
package cvss

import (
	"fmt"
	"math"
	"strings"
)

// Metrics holds the eight CVSS v3.x base metric values, decoded from
// their single-letter vector codes.
type Metrics struct {
	AttackVector       string // N, A, L, P
	AttackComplexity   string // L, H
	PrivilegesRequired string // N, L, H
	UserInteraction    string // N, R
	Scope              string // U, C
	Confidentiality    string // N, L, H
	Integrity          string // N, L, H
	Availability       string // N, L, H
}

var attackVectorWeight = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
var attackComplexityWeight = map[string]float64{"L": 0.77, "H": 0.44}
var userInteractionWeight = map[string]float64{"N": 0.85, "R": 0.62}
var impactWeight = map[string]float64{"N": 0, "L": 0.22, "H": 0.56}

// privilegesRequiredWeight depends on Scope — an exception among the
// base metrics, called out explicitly in the CVSS specification.
var privilegesRequiredWeight = map[string]map[string]float64{
	"U": {"N": 0.85, "L": 0.62, "H": 0.27},
	"C": {"N": 0.85, "L": 0.68, "H": 0.5},
}

var requiredFields = []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

// ParseVector parses a CVSS vector string such as
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" into Metrics.
func ParseVector(vector string) (Metrics, error) {
	parts := strings.Split(vector, "/")
	if len(parts) == 0 || parts[0] == "" {
		return Metrics{}, fmt.Errorf("empty CVSS vector")
	}

	version := parts[0]
	if version != "CVSS:3.0" && version != "CVSS:3.1" {
		return Metrics{}, fmt.Errorf("unsupported CVSS version %q (only CVSS:3.0 and CVSS:3.1 base scoring is implemented)", version)
	}

	fields := make(map[string]string, len(parts)-1)
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return Metrics{}, fmt.Errorf("malformed metric %q in vector", p)
		}
		fields[k] = v
	}

	for _, req := range requiredFields {
		if _, ok := fields[req]; !ok {
			return Metrics{}, fmt.Errorf("vector is missing required base metric %q", req)
		}
	}

	return Metrics{
		AttackVector:       fields["AV"],
		AttackComplexity:   fields["AC"],
		PrivilegesRequired: fields["PR"],
		UserInteraction:    fields["UI"],
		Scope:              fields["S"],
		Confidentiality:    fields["C"],
		Integrity:          fields["I"],
		Availability:       fields["A"],
	}, nil
}

// BaseScore computes the CVSS v3.x base score from m, per the FIRST.org
// specification's base equation.
func BaseScore(m Metrics) (float64, error) {
	av, ok := attackVectorWeight[m.AttackVector]
	if !ok {
		return 0, fmt.Errorf("invalid AV value %q", m.AttackVector)
	}
	ac, ok := attackComplexityWeight[m.AttackComplexity]
	if !ok {
		return 0, fmt.Errorf("invalid AC value %q", m.AttackComplexity)
	}
	ui, ok := userInteractionWeight[m.UserInteraction]
	if !ok {
		return 0, fmt.Errorf("invalid UI value %q", m.UserInteraction)
	}
	prTable, ok := privilegesRequiredWeight[m.Scope]
	if !ok {
		return 0, fmt.Errorf("invalid S (scope) value %q", m.Scope)
	}
	pr, ok := prTable[m.PrivilegesRequired]
	if !ok {
		return 0, fmt.Errorf("invalid PR value %q", m.PrivilegesRequired)
	}
	c, ok := impactWeight[m.Confidentiality]
	if !ok {
		return 0, fmt.Errorf("invalid C value %q", m.Confidentiality)
	}
	i, ok := impactWeight[m.Integrity]
	if !ok {
		return 0, fmt.Errorf("invalid I value %q", m.Integrity)
	}
	a, ok := impactWeight[m.Availability]
	if !ok {
		return 0, fmt.Errorf("invalid A value %q", m.Availability)
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))

	var impact float64
	if m.Scope == "C" {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, nil
	}

	exploitability := 8.22 * av * ac * pr * ui

	if m.Scope == "C" {
		return roundUp(math.Min(1.08*(impact+exploitability), 10)), nil
	}
	return roundUp(math.Min(impact+exploitability, 10)), nil
}

// roundUp implements CVSS's specified "Roundup" function: round up to
// the nearest 0.1, using integer arithmetic to avoid floating-point
// representation error at the boundary — naively computing
// math.Ceil(x*10)/10 on a value that's mathematically exactly 6.0 but
// represented internally as e.g. 6.000000000000001 (a real artifact of
// the preceding multiplications) would wrongly round up to 6.1.
func roundUp(x float64) float64 {
	intInput := int64(math.Round(x * 100000))
	if intInput%10000 == 0 {
		return float64(intInput) / 100000
	}
	return float64((intInput/10000)+1) / 10
}

// Severity maps a CVSS base score to its qualitative rating, per the
// scale published by FIRST.org and used identically by NVD.
func Severity(score float64) string {
	switch {
	case score == 0:
		return "none"
	case score < 4.0:
		return "low"
	case score < 7.0:
		return "medium"
	case score < 9.0:
		return "high"
	default:
		return "critical"
	}
}
