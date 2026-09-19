package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/Shihasz/warden/internal/sbom"
	"github.com/Shihasz/warden/internal/vuln"
	"github.com/Shihasz/warden/internal/vuln/kev"
	"github.com/Shihasz/warden/internal/vuln/osv"
)

type scanOptions struct {
	sbomPath  string
	kevFile   string
	kevCache  string
	kevMaxAge time.Duration
	noKEV     bool
	output    string
}

func newScanCmd() *cobra.Command {
	opts := &scanOptions{}

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan an SBOM's components against OSV.dev for known vulnerabilities",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, opts)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.sbomPath, "sbom", "", "path to a CycloneDX SBOM JSON file, e.g. produced by 'warden sbom generate' (required)")
	f.StringVar(&opts.kevFile, "kev-file", "", "path to a local CISA KEV catalog JSON file, bypassing the network fetch entirely")
	f.StringVar(&opts.kevCache, "kev-cache", defaultKEVCachePath(), "local cache path for the fetched CISA KEV catalog")
	f.DurationVar(&opts.kevMaxAge, "kev-max-age", 24*time.Hour, "how old the cached KEV catalog can be before it's refetched")
	f.BoolVar(&opts.noKEV, "no-kev", false, "skip CISA KEV cross-referencing entirely (nothing will be flagged as known-exploited)")
	f.StringVarP(&opts.output, "output", "o", "", "output file path (defaults to stdout)")

	_ = cmd.MarkFlagRequired("sbom")

	return cmd
}

func defaultKEVCachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "warden-kev-cache.json"
	}
	return filepath.Join(dir, "warden", "kev.json")
}

func runScan(cmd *cobra.Command, opts *scanOptions) error {
	data, err := os.ReadFile(opts.sbomPath)
	if err != nil {
		return fmt.Errorf("read SBOM file: %w", err)
	}

	var bom sbom.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return fmt.Errorf("parse SBOM file: %w", err)
	}
	if len(bom.Components) == 0 {
		return fmt.Errorf("SBOM file %s has no components to scan", opts.sbomPath)
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

	client := osv.NewClient()
	findings, skipped, err := vuln.Scan(ctx, client, catalog, bom.Components)
	if err != nil {
		return fmt.Errorf("scan vulnerabilities: %w", err)
	}

	for _, s := range skipped {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: skipped %s@%s: %s\n", s.Component.Name, s.Component.Version, s.Reason)
	}

	result := struct {
		Findings []vuln.ComponentFinding `json:"findings"`
	}{Findings: findings}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal scan results: %w", err)
	}

	if opts.output == "" {
		_, err = cmd.OutOrStdout().Write(append(out, '\n'))
		return err
	}

	if err := os.WriteFile(opts.output, out, 0o644); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: wrote scan results to %s (%d findings)\n", opts.output, len(findings))
	return nil
}
