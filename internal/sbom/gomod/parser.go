// Package gomod builds SBOM components from a Go module's go.mod and go.sum
// files.
package gomod

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/Shihasz/warden/internal/sbom"
)

// Parse reads goModPath and goSumPath and returns one sbom.Component per
// required module (direct and indirect).
//
// Known limitation: module paths containing uppercase letters are not
// escaped per the Go module proxy's "!"-encoding convention before being
// embedded in the generated purl. This affects a minority of real-world
// module paths; see https://go.dev/ref/mod#module-proxy for the encoding
// this currently skips.
func Parse(goModPath, goSumPath string) ([]sbom.Component, error) {
	modData, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}

	f, err := modfile.Parse(goModPath, modData, nil)
	if err != nil {
		return nil, fmt.Errorf("parse go.mod: %w", err)
	}

	hashes, err := parseGoSum(goSumPath)
	if err != nil {
		return nil, fmt.Errorf("parse go.sum: %w", err)
	}

	components := make([]sbom.Component, 0, len(f.Require))
	for _, req := range f.Require {
		path := req.Mod.Path
		version := req.Mod.Version

		props := []sbom.Property{
			{Name: "gomod:indirect", Value: boolString(req.Indirect)},
		}
		if h, ok := hashes[path+"@"+version]; ok {
			props = append(props, sbom.Property{Name: "gomod:h1", Value: h})
		}

		components = append(components, sbom.Component{
			Type:       "library",
			Name:       path,
			Version:    version,
			PURL:       fmt.Sprintf("pkg:golang/%s@%s", path, version),
			Properties: props,
		})
	}

	return components, nil
}

// parseGoSum reads a go.sum file and returns a map of "module@version" to
// its h1 content hash. Lines ending in "/go.mod" are skipped — those hash
// the dependency's go.mod file specifically, not the module's actual
// source content, and aren't what we want to attach to the component here.
func parseGoSum(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close() // best-effort close; read already completed successfully by this point
	}()

	hashes := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("malformed go.sum line: %q", line)
		}

		modulePath, version, hash := fields[0], fields[1], fields[2]
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}

		hashes[modulePath+"@"+version] = hash
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return hashes, nil
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
