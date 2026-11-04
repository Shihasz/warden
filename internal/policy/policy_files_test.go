package policy

import (
	"reflect"
	"testing"
)

func loadRepoPolicy(t *testing.T, name string) *Policy {
	t.Helper()
	p, err := Load("../../" + name)
	if err != nil {
		t.Fatalf("Load(%s) error = %v", name, err)
	}
	return p
}

// The repository's three policies may differ only in how they treat
// provenance. Everything else is one rule set that must not drift apart.
func TestRepoPolicies_DifferOnlyInProvenance(t *testing.T) {
	strict := loadRepoPolicy(t, "warden-policy.yaml")
	pr := loadRepoPolicy(t, "warden-policy-pr.yaml")
	none := loadRepoPolicy(t, "warden-policy-no-provenance.yaml")

	for name, p := range map[string]*Policy{"pr": pr, "no-provenance": none} {
		if !reflect.DeepEqual(strict.Vulnerabilities, p.Vulnerabilities) {
			t.Errorf("%s policy's vulnerability rules differ from the strict policy's: %+v vs %+v", name, p.Vulnerabilities, strict.Vulnerabilities)
		}
		if !reflect.DeepEqual(strict.Licenses, p.Licenses) {
			t.Errorf("%s policy's license rules differ from the strict policy's: %+v vs %+v", name, p.Licenses, strict.Licenses)
		}
	}

	if !strict.Provenance.Required || strict.Provenance.ExpectedRef == "" {
		t.Errorf("strict policy must require provenance and pin the ref: %+v", strict.Provenance)
	}

	// PR runs: same requirement and minimum level, but no pinned ref
	// (their ref is refs/pull/<n>/merge, never refs/heads/main).
	if !pr.Provenance.Required || pr.Provenance.MinLevel != strict.Provenance.MinLevel ||
		pr.Provenance.ExpectedRepository != strict.Provenance.ExpectedRepository || pr.Provenance.ExpectedRef != "" {
		t.Errorf("PR policy must match the strict one except for the ref pin: %+v vs %+v", pr.Provenance, strict.Provenance)
	}

	if none.Provenance.Required {
		t.Error("the no-provenance policy must not require provenance")
	}
}
