// Package sbom defines a minimal, hand-written subset of the CycloneDX 1.7
// JSON schema (https://cyclonedx.org/docs/1.7/json/) — just the fields
// warden actually needs to describe a software bill of materials. This is
// intentionally not a full implementation of the spec.
package sbom

import "time"

// BOM is the top-level CycloneDX document.
type BOM struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

// Metadata describes when and how the BOM was produced, and what it's about.
type Metadata struct {
	Timestamp time.Time  `json:"timestamp"`
	Component *Component `json:"component,omitempty"`
}

// Component is one entry in the bill of materials — a single dependency.
type Component struct {
	Type       string     `json:"type"` // e.g. "library"
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	PURL       string     `json:"purl,omitempty"` // package URL, e.g. pkg:golang/...
	Hashes     []Hash     `json:"hashes,omitempty"`
	Licenses   []License  `json:"licenses,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

// Hash is a named content hash for a component.
type Hash struct {
	Alg     string `json:"alg"`     // one of CycloneDX's defined algorithm names
	Content string `json:"content"` // hex-encoded digest
}

// License is a single SPDX license identifier attached to a component.
type License struct {
	ID string `json:"id"`
}

// Property is a free-form name/value pair for data that doesn't have a
// dedicated CycloneDX field — this is where we put things like Go's
// non-standard module dirhash.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
