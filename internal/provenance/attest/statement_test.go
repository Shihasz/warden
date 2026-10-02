package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Shihasz/warden/internal/provenance/oidc"
)

func testClaims() *oidc.Claims {
	return &oidc.Claims{
		Repository:        "acme/example",
		Ref:               "refs/heads/main",
		SHA:               "abc123def456",
		Workflow:          "ci",
		WorkflowRef:       "acme/example/.github/workflows/ci.yml@refs/heads/main",
		JobWorkflowRef:    "acme/example/.github/workflows/ci.yml@refs/heads/main",
		RunID:             "987654321",
		RunnerEnvironment: "github-hosted",
		EventName:         "push",
		Actor:             "octocat",
	}
}

func TestBuildStatement(t *testing.T) {
	content := []byte("fake binary content for testing")
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write fixture artifact: %v", err)
	}

	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	stmt, err := BuildStatement(testClaims(), BuildOptions{
		ArtifactPath: path,
		ArtifactName: "warden",
		Now:          now,
	})
	if err != nil {
		t.Fatalf("BuildStatement() error = %v", err)
	}

	if stmt.Type != StatementType {
		t.Errorf("Type = %q, want %q", stmt.Type, StatementType)
	}
	if stmt.PredicateType != SLSAProvenanceType {
		t.Errorf("PredicateType = %q, want %q", stmt.PredicateType, SLSAProvenanceType)
	}

	if len(stmt.Subject) != 1 {
		t.Fatalf("got %d subjects, want 1", len(stmt.Subject))
	}
	sum := sha256.Sum256(content)
	wantDigest := hex.EncodeToString(sum[:])
	if stmt.Subject[0].Digest["sha256"] != wantDigest {
		t.Errorf("subject digest = %q, want %q (computed independently from the same fixture bytes)", stmt.Subject[0].Digest["sha256"], wantDigest)
	}
	if stmt.Subject[0].Name != "warden" {
		t.Errorf("subject name = %q, want warden", stmt.Subject[0].Name)
	}

	bd := stmt.Predicate.BuildDefinition
	if bd.ExternalParameters["repository"] != "https://github.com/acme/example" {
		t.Errorf("externalParameters.repository = %q, want https://github.com/acme/example", bd.ExternalParameters["repository"])
	}
	if bd.ExternalParameters["ref"] != "refs/heads/main" {
		t.Errorf("externalParameters.ref = %q, want refs/heads/main", bd.ExternalParameters["ref"])
	}

	if len(bd.ResolvedDependencies) != 1 {
		t.Fatalf("got %d resolvedDependencies, want 1", len(bd.ResolvedDependencies))
	}
	if bd.ResolvedDependencies[0].Digest["gitCommit"] != "abc123def456" {
		t.Errorf("resolvedDependencies[0].digest.gitCommit = %q, want abc123def456", bd.ResolvedDependencies[0].Digest["gitCommit"])
	}

	rd := stmt.Predicate.RunDetails
	wantBuilderID := "https://github.com/acme/example/.github/workflows/ci.yml@refs/heads/main"
	if rd.Builder.ID != wantBuilderID {
		t.Errorf("builder.id = %q, want %q", rd.Builder.ID, wantBuilderID)
	}
	wantInvocationID := "https://github.com/acme/example/actions/runs/987654321"
	if rd.Metadata.InvocationID != wantInvocationID {
		t.Errorf("metadata.invocationId = %q, want %q", rd.Metadata.InvocationID, wantInvocationID)
	}
	if rd.Metadata.StartedOn != "2026-09-25T12:00:00Z" {
		t.Errorf("metadata.startedOn = %q, want 2026-09-25T12:00:00Z", rd.Metadata.StartedOn)
	}
}
