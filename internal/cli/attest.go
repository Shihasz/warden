package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Shihasz/warden/internal/httpclient"
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
	cmd.AddCommand(newAttestVerifyCmd())
	return cmd
}

type attestSignOptions struct {
	artifactPath string
	artifactName string
	output       string
	pubKeyOutput string
}

func newAttestSignCmd() *cobra.Command {
	opts := &attestSignOptions{}

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Build a SLSA provenance statement for an artifact and sign it",
		Long: "Generates a fresh, ephemeral ed25519 key for this run only, then\n" +
			"requests a GitHub Actions OIDC token whose audience is that key's\n" +
			"fingerprint. GitHub signs the token, so it proves, to anyone who later\n" +
			"checks it against GitHub's published keys, that a specific repository\n" +
			"and workflow run asked for exactly this key.\n\n" +
			"The token is verified here and embedded in a SLSA v1 provenance\n" +
			"statement, which is signed with the ephemeral key in a DSSE envelope.\n" +
			"The key is never persisted or reused across runs; its public half is\n" +
			"written alongside the attestation.\n\n" +
			"Only runs inside a GitHub Actions job granted 'permissions: id-token: write'.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttestSign(cmd, opts)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.artifactPath, "artifact", "", "path to the build artifact to attest (required)")
	f.StringVar(&opts.artifactName, "artifact-name", "", "name recorded for the artifact (defaults to its base filename)")
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

	ctx, cancel := commandContext(cmd)
	defer cancel()
	httpc := httpclient.New()

	// The key must exist before the token is requested: its fingerprint
	// becomes the token's audience, which is what binds the two together.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ephemeral signing key: %w", err)
	}
	audience := attest.BindingAudience(pub)

	token, err := oidc.FetchToken(ctx, httpc, audience)
	if err != nil {
		return fmt.Errorf("fetch OIDC token: %w", err)
	}

	jwks, err := oidc.FetchJWKS(ctx, httpc)
	if err != nil {
		return fmt.Errorf("fetch GitHub's JWKS: %w", err)
	}

	claims, err := oidc.Verify(token, jwks, oidc.VerifyOptions{ExpectedAudience: audience})
	if err != nil {
		return fmt.Errorf("verify OIDC token: %w", err)
	}

	stmt, err := attest.BuildStatement(claims, attest.BuildOptions{
		ArtifactPath: opts.artifactPath,
		ArtifactName: artifactName,
		OIDCToken:    token,
	})
	if err != nil {
		return fmt.Errorf("build provenance statement: %w", err)
	}

	payload, err := json.Marshal(stmt)
	if err != nil {
		return fmt.Errorf("marshal provenance statement: %w", err)
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
