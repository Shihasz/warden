package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"
)

// defaultCommandTimeout is the default for the global --timeout flag.
// It's generous because license and vulnerability lookups are sequential,
// one request per component or vulnerability, so a large lockfile
// legitimately takes minutes.
const defaultCommandTimeout = 10 * time.Minute

// commandContext returns a context bounded by cmd's --timeout flag. A
// timeout of zero or less means no deadline. If the flag isn't defined
// on cmd (which would be a programming error), it falls back to the
// default rather than running unbounded.
func commandContext(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}

	timeout, err := cmd.Flags().GetDuration("timeout")
	if err != nil {
		timeout = defaultCommandTimeout
	}
	if timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}
