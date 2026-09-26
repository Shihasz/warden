// Package classify categorizes SPDX license identifiers/expressions into
// broad classes a policy can act on: permissive, weak copyleft, copyleft,
// or unknown.
//
// This intentionally does not implement the full SPDX license expression
// grammar (parenthesized nesting, WITH exception semantics, arbitrary
// nested AND/OR). It handles the common real-world cases — single
// identifiers and simple "A OR B" / "A AND B" expressions — and falls
// back to Unknown for anything it can't confidently classify, rather
// than guess.
package classify

import "strings"

// Category is a broad license classification.
type Category string

const (
	// Permissive licenses impose minimal restrictions on reuse and
	// redistribution (e.g. MIT, Apache-2.0, BSD variants).
	Permissive Category = "permissive"
	// WeakCopyleft licenses require sharing modifications to the
	// licensed component itself, but not to a larger work that merely
	// links against or uses it (e.g. LGPL, MPL-2.0).
	WeakCopyleft Category = "weak-copyleft"
	// Copyleft licenses can require derivative works — and in some
	// cases software that merely links against the component — to be
	// distributed under the same license (e.g. GPL, AGPL).
	Copyleft Category = "copyleft"
	// Unknown covers anything not present in this package's tables,
	// including deps.dev's explicit "NOASSERTION" sentinel, empty
	// strings, and expressions this package doesn't attempt to parse.
	Unknown Category = "unknown"
)

// rank orders categories from least to most restrictive: used to combine
// multiple licenses in an "AND" expression (take the most restrictive
// combined result) or an "OR" expression (take the least restrictive,
// since the licensee may choose which license to comply with).
var rank = map[Category]int{
	Permissive:   0,
	WeakCopyleft: 1,
	Copyleft:     2,
	Unknown:      3,
}

var permissive = map[string]bool{
	"MIT": true, "MIT-0": true, "0BSD": true,
	"BSD-2-Clause": true, "BSD-3-Clause": true, "BSD-3-Clause-Clear": true,
	"ISC": true, "Apache-1.1": true, "Apache-2.0": true,
	"Zlib": true, "BSL-1.0": true, "Unlicense": true, "CC0-1.0": true,
	"WTFPL": true, "X11": true, "NCSA": true,
	"PSF-2.0": true, "Python-2.0": true,
}

var weakCopyleft = map[string]bool{
	"LGPL-2.0-only": true, "LGPL-2.0-or-later": true,
	"LGPL-2.1-only": true, "LGPL-2.1-or-later": true,
	"LGPL-3.0-only": true, "LGPL-3.0-or-later": true,
	"MPL-1.1": true, "MPL-2.0": true,
	"EPL-1.0": true, "EPL-2.0": true,
	"CDDL-1.0": true, "CDDL-1.1": true, "CPL-1.0": true,
}

var copyleft = map[string]bool{
	"GPL-1.0-only": true, "GPL-1.0-or-later": true,
	"GPL-2.0-only": true, "GPL-2.0-or-later": true,
	"GPL-3.0-only": true, "GPL-3.0-or-later": true,
	"AGPL-1.0": true, "AGPL-1.0-only": true, "AGPL-1.0-or-later": true,
	"AGPL-3.0-only": true, "AGPL-3.0-or-later": true,
	"OSL-3.0": true, "SSPL-1.0": true,
}

// One classifies a single SPDX identifier — no expression operators.
func One(spdxID string) Category {
	id := strings.TrimSpace(spdxID)
	switch {
	case id == "" || id == "NOASSERTION" || id == "NONE":
		return Unknown
	case permissive[id]:
		return Permissive
	case weakCopyleft[id]:
		return WeakCopyleft
	case copyleft[id]:
		return Copyleft
	default:
		return Unknown
	}
}

// Expression classifies a license string that may be a single SPDX
// identifier or a simple "A OR B" / "A AND B" expression. A "WITH
// exception" clause is stripped rather than interpreted — an exception
// can meaningfully change a license's effective obligations (the GPL
// Classpath exception is the classic example), and silently guessing at
// that is worse than classifying conservatively based on the base
// license alone.
func Expression(expr string) Category {
	expr = strings.Trim(strings.TrimSpace(expr), "()")

	if idx := strings.Index(expr, " WITH "); idx != -1 {
		expr = expr[:idx]
	}

	switch {
	case strings.Contains(expr, " OR "):
		return combine(strings.Split(expr, " OR "), minCategory)
	case strings.Contains(expr, " AND "):
		return combine(strings.Split(expr, " AND "), maxCategory)
	default:
		return One(expr)
	}
}

func combine(parts []string, pick func(a, b Category) Category) Category {
	var result Category
	for i, p := range parts {
		c := One(strings.Trim(strings.TrimSpace(p), "()"))
		if i == 0 {
			result = c
			continue
		}
		result = pick(result, c)
	}
	return result
}

func minCategory(a, b Category) Category {
	if rank[a] <= rank[b] {
		return a
	}
	return b
}

func maxCategory(a, b Category) Category {
	if rank[a] >= rank[b] {
		return a
	}
	return b
}

// Classify categorizes every license string in licenses (as returned by
// e.g. the depsdev package) and returns the single most restrictive
// category among them. A component can legitimately have more than one
// applicable license — dual-licensed packages, or deps.dev reporting
// multiple detected licenses for one version — and the most restrictive
// one is what a policy needs to evaluate against.
func Classify(licenses []string) Category {
	if len(licenses) == 0 {
		return Unknown
	}
	result := Unknown
	for i, l := range licenses {
		c := Expression(l)
		if i == 0 {
			result = c
			continue
		}
		result = maxCategory(result, c)
	}
	return result
}
