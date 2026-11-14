package vuln

import (
	"testing"

	"github.com/Shihasz/warden/internal/sbom"
	"github.com/Shihasz/warden/internal/vuln/osv"
)

func TestMerge_KEVMatchesRecordIDAsWellAsAliases(t *testing.T) {
	catalog := writeKEVFixture(t, "CVE-2024-00001")

	findings := []osv.Finding{{
		Component: sbom.Component{Name: "pkg", Version: "1.0.0"},
		Vulns: []osv.Vulnerability{
			{ID: "CVE-2024-00001"}, // identified by the CVE itself, no aliases
			{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"PYSEC-1", "CVE-2024-00001"}}, // CVE among several aliases
			{ID: "GHSA-dddd-eeee-ffff", Aliases: []string{"CVE-2024-99999"}},            // a different CVE
			{ID: "GHSA-gggg-hhhh-iiii"}, // no CVE anywhere
		},
	}}

	got := Merge(findings, catalog)[0].Vulnerabilities
	want := []bool{true, true, false, false}
	if len(got) != len(want) {
		t.Fatalf("got %d vulnerabilities, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].KnownExploited != want[i] {
			t.Errorf("vulnerability %d (%s): KnownExploited = %v, want %v", i, got[i].ID, got[i].KnownExploited, want[i])
		}
	}
}
