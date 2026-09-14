// Package npm builds SBOM components from an npm package-lock.json file
// (lockfileVersion 3, produced by npm 9+).
package npm

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Shihasz/warden/internal/sbom"
)

// cdxHashAlg maps SRI algorithm names to CycloneDX's defined hash algorithm names.
var cdxHashAlg = map[string]string{
	"sha512": "SHA-512",
	"sha384": "SHA-384",
	"sha256": "SHA-256",
	"sha1":   "SHA-1",
}

type packageLock struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]lockPackage `json:"packages"`
}

type lockPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Integrity string `json:"integrity"`
	Dev       bool   `json:"dev"`
	Optional  bool   `json:"optional"`
	Link      bool   `json:"link"`
}

// Parse reads a package-lock.json at lockPath and returns one sbom.Component
// per resolved package. The root project entry (key "") and workspace
// symlinks ("link": true) are skipped — neither is a real, scannable
// dependency.
func Parse(lockPath string) ([]sbom.Component, error) {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("read package-lock.json: %w", err)
	}

	var pl packageLock
	if err := json.Unmarshal(data, &pl); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}

	if pl.LockfileVersion < 2 {
		return nil, fmt.Errorf("lockfileVersion %d (npm <7) is not supported; regenerate the lockfile with a modern npm", pl.LockfileVersion)
	}

	components := make([]sbom.Component, 0, len(pl.Packages))
	for key, pkg := range pl.Packages {
		if key == "" || pkg.Link {
			continue
		}

		name := pkg.Name
		if name == "" {
			name = nameFromPath(key)
		}

		hashes, err := parseIntegrity(pkg.Integrity)
		if err != nil {
			return nil, fmt.Errorf("package %s@%s: %w", name, pkg.Version, err)
		}

		components = append(components, sbom.Component{
			Type:    "library",
			Name:    name,
			Version: pkg.Version,
			PURL:    buildPURL(name, pkg.Version),
			Hashes:  hashes,
			Properties: []sbom.Property{
				{Name: "npm:dev", Value: boolString(pkg.Dev)},
				{Name: "npm:optional", Value: boolString(pkg.Optional)},
			},
		})
	}

	return components, nil
}

// nameFromPath derives a package name from a packages-map key like
// "node_modules/foo" or "node_modules/@scope/foo", including nested
// entries like "node_modules/a/node_modules/@scope/foo". The package name
// is always everything after the *last* "node_modules/" segment — scoped
// names stay intact because npm never inserts another "node_modules/"
// between a scope and its package name.
func nameFromPath(key string) string {
	const marker = "node_modules/"
	if idx := strings.LastIndex(key, marker); idx != -1 {
		return key[idx+len(marker):]
	}
	return key
}

// buildPURL constructs a package URL per the purl spec's npm type
// (https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#npm).
// Scoped packages place the URL-encoded scope in the namespace segment.
func buildPURL(name, version string) string {
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name[1:], "/", 2)
		if len(parts) == 2 {
			return fmt.Sprintf("pkg:npm/%%40%s/%s@%s", parts[0], parts[1], version)
		}
	}
	return fmt.Sprintf("pkg:npm/%s@%s", name, version)
}

// parseIntegrity converts an SRI integrity string (which may contain
// multiple space-separated hashes) into CycloneDX hashes, base64-decoding
// each digest and re-encoding it as hex. Unrecognized algorithms are
// skipped rather than treated as an error, since SRI permits algorithms
// (e.g. future ones) we don't need to support to still coexist safely.
func parseIntegrity(integrity string) ([]sbom.Hash, error) {
	if integrity == "" {
		return nil, nil
	}

	var hashes []sbom.Hash
	for _, field := range strings.Fields(integrity) {
		algo, b64, ok := strings.Cut(field, "-")
		if !ok {
			continue
		}

		cdxAlg, known := cdxHashAlg[algo]
		if !known {
			continue
		}

		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("decode %s integrity value: %w", algo, err)
		}

		hashes = append(hashes, sbom.Hash{
			Alg:     cdxAlg,
			Content: hex.EncodeToString(raw),
		})
	}

	return hashes, nil
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
