package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Shihasz/warden/internal/license/depsdev"
	"github.com/Shihasz/warden/internal/policy"
	"github.com/Shihasz/warden/internal/provenance/attest"
	"github.com/Shihasz/warden/internal/provenance/dsse"
	"github.com/Shihasz/warden/internal/sbom"
	"github.com/Shihasz/warden/internal/vuln"
	"github.com/Shihasz/warden/internal/vuln/kev"
	"github.com/Shihasz/warden/internal/vuln/osv"
)

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Evaluate supply-chain policy",
	}
	cmd.AddCommand(newPolicyCheckCmd())
	return cmd
}

type policyCheckOptions struct {
	sbomPath        string
	policyPath      string
	kevFile         string
	kevCache        string
	kevMaxAge       time.Duration
	noKEV           bool
	attestationPath string
	pubKeyPath      string
	artifactPath    string
	output          string
}

func newPolicyCheckCmd() *cobra.Command {
	opts := &policyCheckOptions{}

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Evaluate an SBOM (and optionally a provenance attestation) against a policy file",
		Long: "Scans the SBOM's components for vulnerabilities (OSV + CISA KEV) and\n" +
			"license issues (deps.dev), optionally verifies a provenance\n" +
			"attestation, and evaluates all three against the given policy file.\n" +
			"Exits non-zero if any policy rule is violated.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyCheck(cmd, opts)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.sbomPath, "sbom", "", "path to a CycloneDX SBOM JSON file (required)")
	f.StringVar(&opts.policyPath, "policy", "", "path to a warden policy YAML file (required)")
	f.StringVar(&opts.kevFile, "kev-file", "", "path to a local CISA KEV catalog JSON file, bypassing the network fetch entirely")
	f.StringVar(&opts.kevCache, "kev-cache", defaultKEVCachePath(), "local cache path for the fetched CISA KEV catalog")
	f.DurationVar(&opts.kevMaxAge, "kev-max-age", 24*time.Hour, "how old the cached KEV catalog can be before it's refetched")
	f.BoolVar(&opts.noKEV, "no-kev", false, "skip CISA KEV cross-referencing entirely")
	f.StringVar(&opts.attestationPath, "attestation", "", "path to a .intoto.jsonl provenance attestation to verify and evaluate")
	f.StringVar(&opts.pubKeyPath, "pubkey", "", "path to the PEM-encoded public key matching --attestation (required if --attestation is set)")
	f.StringVar(&opts.artifactPath, "artifact", "", "path to the build artifact; if set alongside --attestation, its digest is checked against the attestation's subject")
	f.StringVarP(&opts.output, "output", "o", "", "output file path for the policy result (defaults to stdout)")

	_ = cmd.MarkFlagRequired("sbom")
	_ = cmd.MarkFlagRequired("policy")

	return cmd
}

func runPolicyCheck(cmd *cobra.Command, opts *policyCheckOptions) error {
	if opts.attestationPath != "" && opts.pubKeyPath == "" {
		return fmt.Errorf("--pubkey is required when --attestation is set")
	}

	p, err := policy.Load(opts.policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	data, err := os.ReadFile(opts.sbomPath)
	if err != nil {
		return fmt.Errorf("read SBOM file: %w", err)
	}
	var bom sbom.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return fmt.Errorf("parse SBOM file: %w", err)
	}
	if len(bom.Components) == 0 {
		return fmt.Errorf("SBOM file %s has no components to evaluate", opts.sbomPath)
	}

	ctx := context.Background()

	var catalog *kev.Catalog
	if !opts.noKEV {
		if opts.kevFile != "" {
			catalog, err = kev.LoadFile(opts.kevFile)
		} else {
			catalog, err = kev.FetchAndCache(ctx, opts.kevCache, opts.kevMaxAge)
		}
		if err != nil {
			return fmt.Errorf("load KEV catalog: %w", err)
		}
	}

	osvClient := osv.NewClient()
	vulnFindings, vulnSkipped, err := vuln.Scan(ctx, osvClient, catalog, bom.Components)
	if err != nil {
		return fmt.Errorf("scan vulnerabilities: %w", err)
	}
	for _, s := range vulnSkipped {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: skipped vulnerability scan for %s@%s: %s\n", s.Component.Name, s.Component.Version, s.Reason)
	}

	licenseClient := depsdev.NewClient()
	licenseResults, licenseSkipped, err := licenseClient.Lookup(ctx, bom.Components)
	if err != nil {
		return fmt.Errorf("look up licenses: %w", err)
	}
	for _, s := range licenseSkipped {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: skipped license lookup for %s@%s: %s\n", s.Component.Name, s.Component.Version, s.Reason)
	}

	provInput, err := loadProvenanceInput(cmd, opts)
	if err != nil {
		return fmt.Errorf("load provenance attestation: %w", err)
	}

	result := policy.Evaluate(p, vulnFindings, licenseResults, provInput)

	out, err := json.MarshalIndent(struct {
		Passed     bool               `json:"passed"`
		Violations []policy.Violation `json:"violations"`
	}{Passed: result.Passed(), Violations: result.Violations}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal policy result: %w", err)
	}

	if opts.output == "" {
		if _, err := cmd.OutOrStdout().Write(append(out, '\n')); err != nil {
			return err
		}
	} else {
		if err := os.WriteFile(opts.output, out, 0o644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: wrote policy result to %s\n", opts.output)
	}

	if !result.Passed() {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: policy check failed with %d violation(s):\n", len(result.Violations))
		for _, v := range result.Violations {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "  - [%s] %s: %s\n", v.Rule, v.Subject, v.Message)
		}
		return fmt.Errorf("%d policy violation(s)", len(result.Violations))
	}

	return nil
}

// loadProvenanceInput verifies the attestation named by opts, if any.
// Anything that means "there is no verifiable provenance" (a missing
// attestation or public key file, a bad signature, an artifact digest
// mismatch, or a malformed file) is reported as an unverified
// ProvenanceInput rather than aborting the command: whether missing or
// invalid provenance should fail the check is the policy's decision (via
// provenance.required), not this loader's. Other I/O failures, such as
// permission errors, are configuration mistakes and stay hard errors.
func loadProvenanceInput(cmd *cobra.Command, opts *policyCheckOptions) (policy.ProvenanceInput, error) {
	if opts.attestationPath == "" {
		return policy.ProvenanceInput{Verified: false}, nil
	}

	pubPEM, err := os.ReadFile(opts.pubKeyPath)
	if errors.Is(err, fs.ErrNotExist) {
		return unverified(cmd, "public key file not found: %s", opts.pubKeyPath), nil
	}
	if err != nil {
		return policy.ProvenanceInput{}, fmt.Errorf("read public key file: %w", err)
	}
	pub, err := parsePublicKeyPEM(pubPEM)
	if err != nil {
		return policy.ProvenanceInput{}, fmt.Errorf("parse public key: %w", err)
	}

	data, err := os.ReadFile(opts.attestationPath)
	if errors.Is(err, fs.ErrNotExist) {
		return unverified(cmd, "attestation file not found: %s", opts.attestationPath), nil
	}
	if err != nil {
		return policy.ProvenanceInput{}, fmt.Errorf("read attestation file: %w", err)
	}

	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var env dsse.Envelope
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			return unverified(cmd, "malformed attestation line: %v", err), nil
		}

		stmt, err := attest.VerifyEnvelope(&env, pub)
		if err != nil {
			return unverified(cmd, "%v", err), nil
		}

		if opts.artifactPath != "" {
			if err := stmt.CheckArtifactDigest(opts.artifactPath); err != nil {
				return unverified(cmd, "%v", err), nil
			}
		}

		return policy.ProvenanceInput{Verified: true, Statement: stmt}, nil
	}

	return unverified(cmd, "attestation file had no entries"), nil
}

// unverified reports why provenance could not be verified on stderr and
// returns the corresponding unverified ProvenanceInput.
func unverified(cmd *cobra.Command, format string, args ...any) policy.ProvenanceInput {
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: provenance unverified: "+format+"\n", args...)
	return policy.ProvenanceInput{Verified: false}
}
