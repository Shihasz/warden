// Package pip builds SBOM components from Python dependency files.
// ParseRequirements handles requirements.txt.
package pip

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/Shihasz/warden/internal/sbom"
)

// specLine matches a requirement specifier like "name[extra1,extra2]==1.2.3"
// or "name>=1.0" or bare "name". Only "==" is treated as a resolvable pin;
// other operators describe a range, not a specific installed version.
var specLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9.*+!_-]*)?$`)

// RequirementsResult holds parsed components alongside lines that were
// intentionally skipped, so a caller can surface them as warnings instead
// of them silently vanishing from the SBOM.
type RequirementsResult struct {
	Components []sbom.Component
	Skipped    []SkippedLine
}

// SkippedLine records a requirements.txt line warden chose not to convert
// into a component, and why.
type SkippedLine struct {
	Line   string
	Reason string
}

// ParseRequirements reads a requirements.txt file and returns SBOM
// components for every line that resolves to an exact, registry-installable
// package spec.
//
// Known limitations: recursive includes (-r other.txt) are not followed,
// and editable/VCS/URL installs are skipped rather than resolved — neither
// case has a registry version we can attribute a CVE lookup to.
func ParseRequirements(path string) (RequirementsResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return RequirementsResult{}, fmt.Errorf("open requirements file: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	lines, err := joinContinuations(f)
	if err != nil {
		return RequirementsResult{}, fmt.Errorf("read requirements file: %w", err)
	}

	result := RequirementsResult{}
	for _, raw := range lines {
		line := stripComment(raw)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		marker := ""
		if before, after, found := strings.Cut(line, ";"); found {
			line = strings.TrimSpace(before)
			marker = strings.TrimSpace(after)
		}
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "-"):
			result.Skipped = append(result.Skipped, SkippedLine{Line: raw, Reason: "pip option, not a package spec"})
			continue
		case strings.Contains(line, "://"):
			result.Skipped = append(result.Skipped, SkippedLine{Line: raw, Reason: "URL/VCS/editable install, no registry version to attribute"})
			continue
		}

		m := specLine.FindStringSubmatch(line)
		if m == nil {
			result.Skipped = append(result.Skipped, SkippedLine{Line: raw, Reason: "did not match a recognized requirement spec"})
			continue
		}

		rawName, operator, version := m[1], m[3], m[4]
		name := normalizePyPIName(rawName)
		pinned := operator == "==" && version != ""

		resolvedVersion := ""
		purl := "pkg:pypi/" + name
		if pinned {
			resolvedVersion = version
			purl = fmt.Sprintf("pkg:pypi/%s@%s", name, version)
		}

		props := []sbom.Property{
			{Name: "pip:raw-specifier", Value: strings.TrimSpace(raw)},
			{Name: "pip:pinned", Value: boolString(pinned)},
		}
		if marker != "" {
			props = append(props, sbom.Property{Name: "pip:marker", Value: marker})
		}

		result.Components = append(result.Components, sbom.Component{
			Type:       "library",
			Name:       name,
			Version:    resolvedVersion,
			PURL:       purl,
			Properties: props,
		})
	}

	return result, nil
}

// joinContinuations reads all lines from r, joining any line ending in an
// unescaped "\" with the line that follows it (pip's line-continuation
// convention, commonly seen in --hash=... requirements files).
func joinContinuations(f *os.File) ([]string, error) {
	var lines []string
	var pending strings.Builder

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := scanner.Text()
		if strings.HasSuffix(text, "\\") {
			pending.WriteString(strings.TrimSuffix(text, "\\"))
			pending.WriteString(" ")
			continue
		}
		pending.WriteString(text)
		lines = append(lines, pending.String())
		pending.Reset()
	}
	if pending.Len() > 0 {
		lines = append(lines, pending.String())
	}

	return lines, scanner.Err()
}

// stripComment removes a trailing "# ..." comment, but only when the "#" is
// at the start of the line or preceded by whitespace — this avoids
// mangling a "#" that appears inside a URL fragment.
func stripComment(line string) string {
	for i, r := range line {
		if r != '#' {
			continue
		}
		if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
			return line[:i]
		}
	}
	return line
}

// normalizePyPIName applies PEP 503 normalization: lowercase, with any run
// of "-", "_", or "." characters collapsed to a single "-". This makes
// "Flask_SQLAlchemy" and "flask-sqlalchemy" resolve to the same identity,
// which matters once we're matching names against a vulnerability database.
var pep503Runs = regexp.MustCompile(`[-_.]+`)

func normalizePyPIName(name string) string {
	return strings.ToLower(pep503Runs.ReplaceAllString(name, "-"))
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
