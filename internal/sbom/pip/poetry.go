package pip

import (
	"fmt"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/Shihasz/warden/internal/sbom"
)

type poetryLock struct {
	Package []poetryPackage `toml:"package"`
}

type poetryPackage struct {
	Name     string       `toml:"name"`
	Version  string       `toml:"version"`
	Optional bool         `toml:"optional"`
	Groups   []string     `toml:"groups"`
	Category string       `toml:"category"` // legacy (pre-Poetry 1.5) fallback
	Files    []poetryFile `toml:"files"`
}

type poetryFile struct {
	File string `toml:"file"`
	Hash string `toml:"hash"`
}

// ParsePoetryLock reads a poetry.lock file (lock-version 2.0+, i.e. Poetry
// 1.5+, where each package carries its own "files" array) and returns SBOM
// components. Per-file hashes are attached as properties rather than
// CycloneDX hashes, because a package version here can have several
// distinct files (wheel, sdist, per-platform wheels) — there's no single
// hash that correctly identifies "the" component the way npm's one
// integrity value does.
func ParsePoetryLock(path string) ([]sbom.Component, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read poetry.lock: %w", err)
	}

	var lock poetryLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse poetry.lock: %w", err)
	}

	components := make([]sbom.Component, 0, len(lock.Package))
	for _, pkg := range lock.Package {
		name := normalizePyPIName(pkg.Name)

		groups := pkg.Groups
		if len(groups) == 0 && pkg.Category != "" {
			groups = []string{pkg.Category}
		}

		props := []sbom.Property{
			{Name: "pip:groups", Value: strings.Join(groups, ",")},
			{Name: "pip:optional", Value: boolString(pkg.Optional)},
		}
		for _, f := range pkg.Files {
			props = append(props, sbom.Property{
				Name:  "poetry:file:" + f.File,
				Value: f.Hash,
			})
		}

		components = append(components, sbom.Component{
			Type:       "library",
			Name:       name,
			Version:    pkg.Version,
			PURL:       fmt.Sprintf("pkg:pypi/%s@%s", name, pkg.Version),
			Properties: props,
		})
	}

	return components, nil
}
