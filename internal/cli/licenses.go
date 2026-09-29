package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Shihasz/warden/internal/license/classify"
	"github.com/Shihasz/warden/internal/license/depsdev"
	"github.com/Shihasz/warden/internal/sbom"
)

func newLicensesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "licenses",
		Short: "Inspect and check component licenses",
	}
	cmd.AddCommand(newLicensesCheckCmd())
	return cmd
}

type licensesCheckOptions struct {
	sbomPath       string
	denyCategories []string
	output         string
}

func newLicensesCheckCmd() *cobra.Command {
	opts := &licensesCheckOptions{}

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Look up and classify the licenses of an SBOM's components",
		Long: "Looks up each component's license via deps.dev and classifies it as\n" +
			"permissive, weak-copyleft, copyleft, or unknown. With --deny-category,\n" +
			"the command exits non-zero if any component falls into a denied\n" +
			"category. This is a standalone check, not the unified policy engine\n" +
			"(vulnerabilities + provenance + licenses together) planned for a\n" +
			"later phase.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLicensesCheck(cmd, opts)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.sbomPath, "sbom", "", "path to a CycloneDX SBOM JSON file (required)")
	f.StringSliceVar(&opts.denyCategories, "deny-category", nil, "comma-separated categories to fail on: permissive,weak-copyleft,copyleft,unknown")
	f.StringVarP(&opts.output, "output", "o", "", "output file path (defaults to stdout)")

	_ = cmd.MarkFlagRequired("sbom")

	return cmd
}

type licenseFinding struct {
	Component sbom.Component    `json:"component"`
	Licenses  []string          `json:"licenses"`
	Category  classify.Category `json:"category"`
}

func runLicensesCheck(cmd *cobra.Command, opts *licensesCheckOptions) error {
	data, err := os.ReadFile(opts.sbomPath)
	if err != nil {
		return fmt.Errorf("read SBOM file: %w", err)
	}

	var bom sbom.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return fmt.Errorf("parse SBOM file: %w", err)
	}
	if len(bom.Components) == 0 {
		return fmt.Errorf("SBOM file %s has no components to check", opts.sbomPath)
	}

	deny := make(map[classify.Category]bool, len(opts.denyCategories))
	for _, c := range opts.denyCategories {
		deny[classify.Category(c)] = true
	}

	ctx := context.Background()
	client := depsdev.NewClient()
	results, skipped, err := client.Lookup(ctx, bom.Components)
	if err != nil {
		return fmt.Errorf("look up licenses: %w", err)
	}

	for _, s := range skipped {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: skipped %s@%s: %s\n", s.Component.Name, s.Component.Version, s.Reason)
	}

	findings := make([]licenseFinding, 0, len(results))
	var violations []licenseFinding
	for _, r := range results {
		category := classify.Classify(r.Licenses)
		f := licenseFinding{Component: r.Component, Licenses: r.Licenses, Category: category}
		findings = append(findings, f)
		if deny[category] {
			violations = append(violations, f)
		}
	}

	out, err := json.MarshalIndent(struct {
		Findings []licenseFinding `json:"findings"`
	}{Findings: findings}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal license report: %w", err)
	}

	if opts.output == "" {
		if _, err := cmd.OutOrStdout().Write(append(out, '\n')); err != nil {
			return err
		}
	} else {
		if err := os.WriteFile(opts.output, out, 0o644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: wrote license report to %s (%d components)\n", opts.output, len(findings))
	}

	if len(violations) > 0 {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: %d component(s) violate denied license categories:\n", len(violations))
		for _, v := range violations {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "  - %s@%s: %v (%s)\n", v.Component.Name, v.Component.Version, v.Licenses, v.Category)
		}
		return fmt.Errorf("%d component(s) violate denied license categories", len(violations))
	}

	return nil
}
