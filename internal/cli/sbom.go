package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Shihasz/warden/internal/sbom"
	"github.com/Shihasz/warden/internal/sbom/gomod"
	"github.com/Shihasz/warden/internal/sbom/npm"
	"github.com/Shihasz/warden/internal/sbom/pip"
)

func newSBOMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Generate and inspect software bills of materials",
	}
	cmd.AddCommand(newSBOMGenerateCmd())
	return cmd
}

type sbomGenerateOptions struct {
	goMod           string
	goSum           string
	npmLock         string
	pipRequirements string
	poetryLock      string
	projectName     string
	output          string
}

func newSBOMGenerateCmd() *cobra.Command {
	opts := &sbomGenerateOptions{}

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a CycloneDX SBOM from one or more dependency files",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSBOMGenerate(cmd, opts)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.goMod, "go-mod", "", "path to go.mod")
	f.StringVar(&opts.goSum, "go-sum", "", "path to go.sum (required with --go-mod)")
	f.StringVar(&opts.npmLock, "npm-lock", "", "path to package-lock.json")
	f.StringVar(&opts.pipRequirements, "pip-requirements", "", "path to requirements.txt")
	f.StringVar(&opts.poetryLock, "poetry-lock", "", "path to poetry.lock")
	f.StringVar(&opts.projectName, "name", "", "name of the project this SBOM describes")
	f.StringVarP(&opts.output, "output", "o", "", "output file path (defaults to stdout)")

	return cmd
}

func runSBOMGenerate(cmd *cobra.Command, opts *sbomGenerateOptions) error {
	if opts.goMod != "" && opts.goSum == "" {
		return fmt.Errorf("--go-sum is required when --go-mod is set")
	}

	var components []sbom.Component

	if opts.goMod != "" {
		c, err := gomod.Parse(opts.goMod, opts.goSum)
		if err != nil {
			return fmt.Errorf("go modules: %w", err)
		}
		components = append(components, c...)
	}

	if opts.npmLock != "" {
		c, err := npm.Parse(opts.npmLock)
		if err != nil {
			return fmt.Errorf("npm: %w", err)
		}
		components = append(components, c...)
	}

	if opts.pipRequirements != "" {
		result, err := pip.ParseRequirements(opts.pipRequirements)
		if err != nil {
			return fmt.Errorf("pip requirements: %w", err)
		}
		components = append(components, result.Components...)
		for _, s := range result.Skipped {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: skipped requirements.txt line %q: %s\n", s.Line, s.Reason)
		}
	}

	if opts.poetryLock != "" {
		c, err := pip.ParsePoetryLock(opts.poetryLock)
		if err != nil {
			return fmt.Errorf("poetry: %w", err)
		}
		components = append(components, c...)
	}

	if len(components) == 0 {
		return fmt.Errorf("no dependency files given — pass at least one of --go-mod, --npm-lock, --pip-requirements, --poetry-lock")
	}

	serial, err := sbom.NewSerialNumber()
	if err != nil {
		return fmt.Errorf("generate serial number: %w", err)
	}

	bom := sbom.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.7",
		SerialNumber: serial,
		Version:      1,
		Metadata: sbom.Metadata{
			Timestamp: time.Now().UTC(),
		},
		Components: components,
	}
	if opts.projectName != "" {
		bom.Metadata.Component = &sbom.Component{
			Type: "application",
			Name: opts.projectName,
		}
	}

	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal SBOM: %w", err)
	}

	if opts.output == "" {
		_, err = cmd.OutOrStdout().Write(append(data, '\n'))
		return err
	}

	if err := os.WriteFile(opts.output, data, 0o644); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: wrote SBOM to %s (%d components)\n", opts.output, len(components))
	return nil
}
