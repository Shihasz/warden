// Package cli defines warden's command-line interface.
package cli

import "github.com/spf13/cobra"

// NewRootCmd builds the root warden command. version is reported by
// `warden --version`; pass "dev" for local builds, or a real version
// injected via -ldflags at release build time.
func NewRootCmd(version string) *cobra.Command {
	root := &cobra.Command{
		Use:   "warden",
		Short: "warden is a software supply-chain security gate",
		Long: "warden generates SBOMs, scans dependencies for known vulnerabilities,\n" +
			"verifies build provenance, and evaluates the result against policy —\n" +
			"designed to run as a real gate in a CI/CD pipeline.",
		Version: version,
		// We print our own error format in main(), so cobra shouldn't
		// also print its own copy of the same error and a usage block.
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	root.AddCommand(newSBOMCmd())
	root.AddCommand(newScanCmd())

	return root
}
