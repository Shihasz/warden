package attest

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/Shihasz/warden/internal/provenance/dsse"
)

// VerifyEnvelope checks env's DSSE signature against pub and parses the
// resulting payload into a Statement. It does not check the statement's
// contents (artifact digest, repository identity, etc.) — see
// CheckArtifactDigest and CheckIdentity for that.
func VerifyEnvelope(env *dsse.Envelope, pub ed25519.PublicKey) (*Statement, error) {
	if env.PayloadType != "application/vnd.in-toto+json" {
		return nil, fmt.Errorf("unexpected payload type %q", env.PayloadType)
	}

	payload, err := dsse.Verify(env, pub)
	if err != nil {
		return nil, fmt.Errorf("verify DSSE signature: %w", err)
	}

	var stmt Statement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, fmt.Errorf("parse statement: %w", err)
	}
	if stmt.Type != StatementType {
		return nil, fmt.Errorf("unexpected statement type %q, want %q", stmt.Type, StatementType)
	}
	if stmt.PredicateType != SLSAProvenanceType {
		return nil, fmt.Errorf("unexpected predicate type %q, want %q", stmt.PredicateType, SLSAProvenanceType)
	}

	return &stmt, nil
}

// CheckArtifactDigest verifies that artifactPath's current SHA-256
// digest matches one of the statement's subjects — i.e. that the file on
// disk is actually the exact artifact this statement was issued for.
func (s *Statement) CheckArtifactDigest(artifactPath string) error {
	digest, err := sha256File(artifactPath)
	if err != nil {
		return fmt.Errorf("digest artifact: %w", err)
	}
	for _, subj := range s.Subject {
		if want, ok := subj.Digest["sha256"]; ok && want == digest {
			return nil
		}
	}
	return fmt.Errorf("artifact digest %s does not match any subject in the statement", digest)
}

// ExpectedIdentity constrains what a verified statement's build identity
// must match. A zero-value field means "don't check this".
type ExpectedIdentity struct {
	Repository string // e.g. "https://github.com/acme/example"
	Ref        string // e.g. "refs/heads/main"
}

// CheckIdentity verifies the statement's recorded build identity matches
// exp.
func (s *Statement) CheckIdentity(exp ExpectedIdentity) error {
	ep := s.Predicate.BuildDefinition.ExternalParameters
	if exp.Repository != "" && ep["repository"] != exp.Repository {
		return fmt.Errorf("attested repository %q does not match expected %q", ep["repository"], exp.Repository)
	}
	if exp.Ref != "" && ep["ref"] != exp.Ref {
		return fmt.Errorf("attested ref %q does not match expected %q", ep["ref"], exp.Ref)
	}
	return nil
}
