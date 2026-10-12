package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// stderrWarnf returns a printf-style reporter that writes
// "warden: warning: <message>" lines to cmd's stderr, for passing to
// library code that reports non-fatal problems through a callback.
func stderrWarnf(cmd *cobra.Command) func(format string, args ...any) {
	return func(format string, args ...any) {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warden: warning: "+format+"\n", args...)
	}
}
