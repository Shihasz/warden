package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Shihasz/warden/internal/provenance/attest"
	"github.com/Shihasz/warden/internal/provenance/dsse"
	"github.com/Shihasz/warden/internal/provenance/oidc"
)

const inTotoPayloadType = "application/vnd.in-toto+json"

func newAttestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Build and sign provenance attestations",
	}
	cmd.AddCommand(newAttestSignCmd())
	return cmd
}

type attestSignOptions struct {
	artifactPath string
	artifactName string
	audience     string
	output       string
	pubKeyOutput string
}

func newAttestSignCmd() *cobra.Command {
	opts := &attestSignOptions{}

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Build a SLSA provenance statement for an artifact and sign it",
		Long: "Fetches and verifies a GitHub Actions OIDC token to establish who is\n" +
			"running this build, builds a SLSA v1 provenance statement from that\n" +
			"verified identity, and signs it in a DSSE envelope using a fresh,\n" +
			"ephemeral ed25519 key generated for this run only.\n\n" +
			"The signing key is never persisted or reused across runs. Trust in\n" +
			"the attestation comes from the OIDC-verified claims recorded inside\n" +
			"the provenance statement itself (which repository, which workflow,\n" +
			"which commit) — not from the signing key's identity. The public key\n" +
			"is written alongside the signature so a verifier can confirm the\n" +
			"envelope wasn't altered after this signing operation.\n\n" +
			"Only runs inside a GitHub Actions job granted 'permissions: id-token: write'.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttestSign(cmd, opts)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.artifactPath, "artifact", "", "path to the build artifact to attest (required)")
	f.StringVar(&opts.artifactName, "artifact-name", "", "name recorded for the artifact (defaults to its base filename)")
	f.StringVar(&opts.audience, "audience", "warden", "OIDC audience to request the token for; a verifier must check for the same value")
	f.StringVarP(&opts.output, "output", "o", "", "path to write the signed DSSE envelope (defaults to <artifact>.intoto.jsonl)")
	f.StringVar(&opts.pubKeyOutput, "pubkey-output", "", "path to write the ephemeral public key as PEM (defaults to <output>.pub)")

	_ = cmd.MarkFlagRequired("artifact")

	return cmd
}

func runAttestSign(cmd *cobra.Command, opts *attestSignOptions) error {
	if _, err := os.Stat(opts.artifactPath); err != nil {
		return fmt.Errorf("artifact not found: %w", err)
	}

	artifactName := opts.artifactName
	if artifactName == "" {
		artifactName = filepath.Base(opts.artifactPath)
	}
	output := opts.output
	if output == "" {
		output = opts.artifactPath + ".intoto.jsonl"
	}
	pubKeyOutput := opts.pubKeyOutput
	if pubKeyOutput == "" {
		pubKeyOutput = output + ".pub"
	}

	ctx := context.Background()

	token, err := oidc.FetchToken(ctx, http.DefaultClient, opts.audience)
	if err != nil {
		return fmt.Errorf("fetch OIDC token: %w", err)
	}

	jwks, err := oidc.FetchJWKS(ctx, http.DefaultClient)
	if err != nil {
		return fmt.Errorf("fetch GitHub's JWKS: %w", err)
	}

	claims, err := oidc.Verify(token, jwks, oidc.VerifyOptions{ExpectedAudience: opts.audience})
	if err != nil {
		return fmt.Errorf("verify OIDC token: %w", err)
	}

	stmt, err := attest.BuildStatement(claims, attest.BuildOptions{
		ArtifactPath: opts.artifactPath,
		ArtifactName: artifactName,
	})
	if err != nil {
		return fmt.Errorf("build provenance statement: %w", err)
	}

	payload, err := json.Marshal(stmt)
	if err != nil {
		return fmt.Errorf("marshal provenance statement: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ephemeral signing key: %w", err)
	}

	env, err := dsse.Sign(inTotoPayloadType, payload, priv, dsse.KeyID(pub))
	if err != nil {
		return fmt.Errorf("sign attestation: %w", err)
	}

	envJSON, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal signed envelope: %w", err)
	}
	if err := os.WriteFile(output, append(envJSON, '\n'), 0o644); err != nil {
		return fmt.Errorf("write attestation file: %w", err)
	}

	pubPEM, err := encodePublicKeyPEM(pub)
	if err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}
	if err := os.WriteFile(pubKeyOutput, pubPEM, 0o644); err != nil {
		return fmt.Errorf("write public key file: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: wrote attestation to %s\n", output)
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: wrote ephemeral public key to %s (keyid %s)\n", pubKeyOutput, dsse.KeyID(pub))
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: attested repository=%s ref=%s sha=%s workflow=%s\n", claims.Repository, claims.Ref, claims.SHA, claims.WorkflowRef)

	return nil
}

func encodePublicKeyPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return pem.EncodeToMemory(block), nil
}
