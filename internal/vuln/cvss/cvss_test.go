package cvss

import (
	"math"
	"testing"
)

// These two vectors and their expected scores come from a fully worked
// example (including every intermediate value: ISS, Impact,
// Exploitability) that was hand-verified against this package's formula
// before writing the implementation — not just a number taken on faith.
func TestBaseScore_KnownVectors(t *testing.T) {
	cases := []struct {
		name         string
		vector       string
		wantScore    float64
		wantSeverity string
	}{
		{
			name:         "worst case — all high impact, no privileges, no interaction",
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantScore:    9.8,
			wantSeverity: "critical",
		},
		{
			name:         "low-privilege, confidentiality-only impact",
			vector:       "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
			wantScore:    6.5,
			wantSeverity: "medium",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParseVector(tc.vector)
			if err != nil {
				t.Fatalf("ParseVector(%q) error = %v", tc.vector, err)
			}

			score, err := BaseScore(m)
			if err != nil {
				t.Fatalf("BaseScore() error = %v", err)
			}
			if math.Abs(score-tc.wantScore) > 0.001 {
				t.Errorf("BaseScore() = %v, want %v", score, tc.wantScore)
			}

			if got := Severity(score); got != tc.wantSeverity {
				t.Errorf("Severity(%v) = %q, want %q", score, got, tc.wantSeverity)
			}
		})
	}
}

func TestParseVector_RejectsUnsupportedVersions(t *testing.T) {
	cases := []string{
		"AV:N/AC:L/Au:N/C:C/I:C/A:C",                                      // CVSS v2 has no "CVSS:" version prefix at all
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", // v4 uses a different metric set
		"CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
	}
	for _, v := range cases {
		if _, err := ParseVector(v); err == nil {
			t.Errorf("ParseVector(%q) should reject unsupported CVSS versions, got nil error", v)
		}
	}
}

func TestParseVector_RejectsMissingMetric(t *testing.T) {
	// Missing "A:" (availability) entirely
	v := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"
	if _, err := ParseVector(v); err == nil {
		t.Error("ParseVector() with a missing required metric should return an error, got nil")
	}
}

func TestSeverity_BoundaryValues(t *testing.T) {
	cases := map[float64]string{
		0.0:  "none",
		0.1:  "low",
		3.9:  "low",
		4.0:  "medium",
		6.9:  "medium",
		7.0:  "high",
		8.9:  "high",
		9.0:  "critical",
		10.0: "critical",
	}
	for score, want := range cases {
		if got := Severity(score); got != want {
			t.Errorf("Severity(%v) = %q, want %q", score, got, want)
		}
	}
}
