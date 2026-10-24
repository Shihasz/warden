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
	"github.com/Shihasz/warden/internal/provenance/oidc"
)

type attestVerifyOptions struct {
	attestationPath string
	pubKeyPath      string
	artifactPath    string
	expectRepo      string
	expectRef       string
	jwksFile        string
	allowUnbound    bool
}

func newAttestVerifyCmd() *cobra.Command {
	opts := &attestVerifyOptions{}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a signed provenance attestation",
		Long: "Checks a DSSE-signed attestation's signature against a public key,\n" +
			"then proves the key belongs to a GitHub Actions run: the embedded\n" +
			"OIDC token must carry a valid GitHub signature, name this exact key\n" +
			"as its audience, and agree with every identity claim in the statement.\n" +
			"Optionally checks the artifact's digest and the expected repository\n" +
			"and ref. Every line of the attestation file is verified independently.\n\n" +
			"Without the OIDC token binding, a valid signature proves only that\n" +
			"the file wasn't altered after signing: anyone can sign a statement\n" +
			"claiming any repository. Such attestations are rejected unless\n" +
			"--allow-unbound is given.",
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
	f.StringVar(&opts.jwksFile, "jwks-file", "", "path to a JWKS JSON file used to check the OIDC token, instead of fetching GitHub's published keys")
	f.BoolVar(&opts.allowUnbound, "allow-unbound", false, "accept attestations with no embedded OIDC token; their claims are self-asserted")

	_ = cmd.MarkFlagRequired("attestation")
	_ = cmd.MarkFlagRequired("pubkey")

	return cmd
}

func runAttestVerify(cmd *cobra.Command, opts *attestVerifyOptions) error {
	ctx, cancel := commandContext(cmd)
	defer cancel()

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

	// Loaded lazily: an unbound attestation is rejected (or accepted
	// with a warning) without ever touching the network.
	var jwks *oidc.JWKS
	getJWKS := func() (*oidc.JWKS, error) {
		if jwks == nil {
			loaded, err := loadJWKS(ctx, opts.jwksFile)
			if err != nil {
				return nil, err
			}
			jwks = loaded
		}
		return jwks, nil
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

		bound := stmt.HasOIDCToken()
		switch {
		case bound:
			keys, err := getJWKS()
			if err != nil {
				return fmt.Errorf("line %d: load the keys needed to check the OIDC token: %w", i+1, err)
			}
			// A token that is present must be valid even with
			// --allow-unbound: a bad token is a red flag, not an omission.
			if _, err := stmt.VerifyBinding(pub, keys); err != nil {
				return fmt.Errorf("line %d: %w", i+1, err)
			}
		case opts.allowUnbound:
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: WARNING: attestation %d is not bound to a GitHub identity, so its claims are self-asserted and prove nothing about who built the artifact\n", i+1)
		default:
			return fmt.Errorf("line %d: %w (pass --allow-unbound only if you accept that)", i+1, attest.ErrNoOIDCToken)
		}

		verified++
		status := "signing key bound to a GitHub-signed identity"
		if !bound {
			status = "UNBOUND, claims are self-asserted"
		}
		ep := stmt.Predicate.BuildDefinition.ExternalParameters
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: verified attestation %d: repository=%s ref=%s (%s)\n", i+1, ep["repository"], ep["ref"], status)
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
