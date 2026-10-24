// Package attest builds in-toto Statement / SLSA v1 Provenance
// attestations describing a build, using a verified GitHub Actions OIDC
// identity (see internal/provenance/oidc) as the source of truth for who
// performed the build.
package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Shihasz/warden/internal/provenance/oidc"
)

// StatementType is the in-toto Statement layer's type identifier.
const StatementType = "https://in-toto.io/Statement/v1"

// SLSAProvenanceType is the SLSA Provenance predicate's type identifier.
// Per the spec's own parsing rules, this string is always written with
// the major version only ("v1"), regardless of which SLSA minor version
// (e.g. 1.2) is actually in effect.
const SLSAProvenanceType = "https://slsa.dev/provenance/v1"

// BuildType identifies warden's own build-definition schema — this is
// warden's documented convention, not a claim of matching any other
// tool's internal format.
const BuildType = "https://github.com/Shihasz/warden/buildtypes/github-actions/v1"

// Statement is an in-toto Statement carrying a SLSA v1 Provenance
// predicate — the subset of both specs warden actually populates.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Subject identifies the artifact this statement is about.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Predicate is the SLSA v1 Provenance predicate.
type Predicate struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

// BuildDefinition describes what was built and how.
type BuildDefinition struct {
	BuildType            string               `json:"buildType"`
	ExternalParameters   map[string]string    `json:"externalParameters"`
	InternalParameters   map[string]string    `json:"internalParameters,omitempty"`
	ResolvedDependencies []ResourceDescriptor `json:"resolvedDependencies,omitempty"`
}

// ResourceDescriptor identifies a resource: a dependency the build used,
// or a byproduct it produced.
type ResourceDescriptor struct {
	URI       string            `json:"uri,omitempty"`
	Digest    map[string]string `json:"digest,omitempty"`
	Name      string            `json:"name,omitempty"`
	MediaType string            `json:"mediaType,omitempty"`
	// Content is base64-encoded on the wire, as the SLSA spec requires;
	// encoding/json does that automatically for []byte.
	Content []byte `json:"content,omitempty"`
}

// RunDetails describes the specific build run.
type RunDetails struct {
	Builder    Builder              `json:"builder"`
	Metadata   BuildMetadata        `json:"metadata,omitempty"`
	Byproducts []ResourceDescriptor `json:"byproducts,omitempty"`
}

// Builder identifies the entity that ran the build.
type Builder struct {
	ID string `json:"id"`
}

// BuildMetadata carries details about this specific invocation.
type BuildMetadata struct {
	InvocationID string `json:"invocationId,omitempty"`
	StartedOn    string `json:"startedOn,omitempty"`
}

// BuildOptions are the pieces of a Statement not derivable from the OIDC
// claims alone.
type BuildOptions struct {
	// ArtifactPath is the file to compute a SHA-256 digest for and
	// describe as the statement's subject.
	ArtifactPath string
	// ArtifactName is the name recorded for the subject — typically just
	// the artifact's base filename.
	ArtifactName string
	// OIDCToken, if set, is the GitHub Actions OIDC token to embed as a
	// byproduct, so a verifier can check GitHub's signature on it.
	OIDCToken string
	// Now is used for the statement's startedOn timestamp; defaults to
	// time.Now if zero. Overridable so tests don't depend on wall-clock
	// time.
	Now time.Time
}

// BuildStatement constructs a Statement from verified GitHub Actions OIDC
// claims and the artifact being attested. The claims are assumed already
// cryptographically verified by oidc.Verify — this function trusts them
// as-is and does no further validation of the identity itself.
func BuildStatement(claims *oidc.Claims, opts BuildOptions) (*Statement, error) {
	digest, err := sha256File(opts.ArtifactPath)
	if err != nil {
		return nil, fmt.Errorf("digest artifact: %w", err)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	definition, builder, invocationID := identityFromClaims(claims)

	stmt := &Statement{
		Type: StatementType,
		Subject: []Subject{
			{Name: opts.ArtifactName, Digest: map[string]string{"sha256": digest}},
		},
		PredicateType: SLSAProvenanceType,
		Predicate: Predicate{
			BuildDefinition: definition,
			RunDetails: RunDetails{
				Builder: builder,
				Metadata: BuildMetadata{
					InvocationID: invocationID,
					StartedOn:    now.UTC().Format(time.RFC3339),
				},
			},
		},
	}

	if opts.OIDCToken != "" {
		stmt.Predicate.RunDetails.Byproducts = []ResourceDescriptor{{
			Name:      OIDCTokenName,
			MediaType: OIDCTokenMediaType,
			Content:   []byte(opts.OIDCToken),
		}}
	}

	return stmt, nil
}

// identityFromClaims derives every identity-bearing field of a statement
// from GitHub's OIDC claims. BuildStatement uses it to produce those
// fields and VerifyBinding uses it to check them against a GitHub-signed
// token, so the two can never drift apart.
func identityFromClaims(claims *oidc.Claims) (BuildDefinition, Builder, string) {
	repoURL := "https://github.com/" + claims.Repository

	definition := BuildDefinition{
		BuildType: BuildType,
		ExternalParameters: map[string]string{
			"repository": repoURL,
			"ref":        claims.Ref,
			"workflow":   claims.WorkflowRef,
		},
		InternalParameters: map[string]string{
			"runnerEnvironment": claims.RunnerEnvironment,
			"eventName":         claims.EventName,
			"actor":             claims.Actor,
		},
		ResolvedDependencies: []ResourceDescriptor{
			{
				URI:    fmt.Sprintf("git+%s@%s", repoURL, claims.Ref),
				Digest: map[string]string{"gitCommit": claims.SHA},
			},
		},
	}

	// warden's own builder.id convention: a URI built from the
	// OIDC-verified job_workflow_ref claim, which already uniquely
	// identifies the exact workflow file and ref that ran this job.
	builder := Builder{ID: "https://github.com/" + claims.JobWorkflowRef}

	invocationID := fmt.Sprintf("%s/actions/runs/%s", repoURL, claims.RunID)

	return definition, builder, invocationID
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = f.Close()
	}()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
