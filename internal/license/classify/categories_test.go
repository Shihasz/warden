package classify

import (
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	for _, c := range []Category{Permissive, WeakCopyleft, Copyleft, Unknown} {
		if !Valid(c) {
			t.Errorf("Valid(%q) = false, want true", c)
		}
	}
	for _, c := range []Category{"", "Copyleft", "copyleftt", "none", "weak_copyleft"} {
		if Valid(c) {
			t.Errorf("Valid(%q) = true, want false", c)
		}
	}
}

func TestList_NamesEveryCategory(t *testing.T) {
	list := List()
	for _, c := range Categories() {
		if !strings.Contains(list, string(c)) {
			t.Errorf("List() = %q, missing %q", list, c)
		}
	}
}
