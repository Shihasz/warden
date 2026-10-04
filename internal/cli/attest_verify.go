package cli

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Shihasz/warden/internal/provenance/attest"
	"github.com/Shihasz/warden/internal/provenance/dsse"
)

type attestVerifyOptions struct {
	attestationPath string
	pubKeyPath      string
	artifactPath    string
	expectRepo      string
	expectRef       string
}

func newAttestVerifyCmd() *cobra.Command {
	opts := &attestVerifyOptions{}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a signed provenance attestation",
		Long: "Checks a DSSE-signed attestation's signature against a public key,\n" +
			"and optionally checks the attested artifact digest and build identity\n" +
			"(repository, ref) against expected values. Every line of the\n" +
			"attestation file is verified independently.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttestVerify(cmd, opts)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.attestationPath, "attestation", "", "path to the .intoto.jsonl attestation file (required)")
	f.StringVar(&opts.pubKeyPath, "pubkey", "", "path to the PEM-encoded public key to verify against (required)")
	f.StringVar(&opts.artifactPath, "artifact", "", "path to the artifact file; if set, its digest is checked against the attestation's subject")
	f.StringVar(&opts.expectRepo, "expect-repository", "", "require the attested repository to equal this exact value")
	f.StringVar(&opts.expectRef, "expect-ref", "", "require the attested ref to equal this exact value")

	_ = cmd.MarkFlagRequired("attestation")
	_ = cmd.MarkFlagRequired("pubkey")

	return cmd
}

func runAttestVerify(cmd *cobra.Command, opts *attestVerifyOptions) error {
	pubPEM, err := os.ReadFile(opts.pubKeyPath)
	if err != nil {
		return fmt.Errorf("read public key file: %w", err)
	}
	pub, err := parsePublicKeyPEM(pubPEM)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	data, err := os.ReadFile(opts.attestationPath)
	if err != nil {
		return fmt.Errorf("read attestation file: %w", err)
	}

	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	verified := 0
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var env dsse.Envelope
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			return fmt.Errorf("line %d: parse envelope: %w", i+1, err)
		}

		stmt, err := attest.VerifyEnvelope(&env, pub)
		if err != nil {
			return fmt.Errorf("line %d: %w", i+1, err)
		}

		if opts.artifactPath != "" {
			if err := stmt.CheckArtifactDigest(opts.artifactPath); err != nil {
				return fmt.Errorf("line %d: %w", i+1, err)
			}
		}
		if opts.expectRepo != "" || opts.expectRef != "" {
			if err := stmt.CheckIdentity(attest.ExpectedIdentity{Repository: opts.expectRepo, Ref: opts.expectRef}); err != nil {
				return fmt.Errorf("line %d: %w", i+1, err)
			}
		}

		verified++
		ep := stmt.Predicate.BuildDefinition.ExternalParameters
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: verified attestation %d: repository=%s ref=%s\n", i+1, ep["repository"], ep["ref"])
	}

	if verified == 0 {
		return fmt.Errorf("attestation file %s had no valid entries", opts.attestationPath)
	}

	return nil
}

func parsePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ed25519 (got %T)", pub)
	}
	return edPub, nil
}
