package classify

import "testing"

func TestOne(t *testing.T) {
	cases := map[string]Category{
		"MIT":             Permissive,
		"Apache-2.0":      Permissive,
		"BSD-3-Clause":    Permissive,
		"LGPL-2.1-only":   WeakCopyleft,
		"MPL-2.0":         WeakCopyleft,
		"GPL-3.0-only":    Copyleft,
		"AGPL-3.0-only":   Copyleft,
		"NOASSERTION":     Unknown,
		"":                Unknown,
		"Some-Made-Up-ID": Unknown,
	}
	for id, want := range cases {
		if got := One(id); got != want {
			t.Errorf("One(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestExpression(t *testing.T) {
	cases := map[string]Category{
		"MIT OR Apache-2.0":                         Permissive,
		"LGPL-2.1-only OR GPL-2.0-only":             WeakCopyleft, // OR: least restrictive choice available
		"MIT AND GPL-3.0-only":                      Copyleft,     // AND: both apply, most restrictive wins
		"GPL-2.0-only WITH Classpath-exception-2.0": Copyleft,     // WITH clause stripped; base license still classified
		"(MIT)": Permissive,
	}
	for expr, want := range cases {
		if got := Expression(expr); got != want {
			t.Errorf("Expression(%q) = %q, want %q", expr, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	if got := Classify(nil); got != Unknown {
		t.Errorf("Classify(nil) = %q, want %q", got, Unknown)
	}
	if got := Classify([]string{}); got != Unknown {
		t.Errorf("Classify([]) = %q, want %q", got, Unknown)
	}
	if got := Classify([]string{"MIT"}); got != Permissive {
		t.Errorf("Classify([MIT]) = %q, want %q", got, Permissive)
	}
	// Dual-licensed under two different single licenses (not an "A OR B"
	// expression in one string, but two separate entries, as deps.dev
	// can return) — the most restrictive of the two wins.
	if got := Classify([]string{"MIT", "GPL-3.0-only"}); got != Copyleft {
		t.Errorf("Classify([MIT, GPL-3.0-only]) = %q, want %q", got, Copyleft)
	}
}
