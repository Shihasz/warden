package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func newCmdWithTimeout(t *testing.T, value string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().Duration("timeout", defaultCommandTimeout, "")
	if err := cmd.Flags().Set("timeout", value); err != nil {
		t.Fatalf("set timeout flag: %v", err)
	}
	return cmd
}

func TestCommandContext_AppliesTimeout(t *testing.T) {
	ctx, cancel := commandContext(newCmdWithTimeout(t, "2s"))
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("context has no deadline, want one from --timeout")
	}
	if remaining := time.Until(deadline); remaining <= 0 || remaining > 2*time.Second {
		t.Errorf("remaining = %v, want within (0, 2s]", remaining)
	}
}

func TestCommandContext_ZeroMeansNoDeadline(t *testing.T) {
	ctx, cancel := commandContext(newCmdWithTimeout(t, "0"))
	defer cancel()

	if _, ok := ctx.Deadline(); ok {
		t.Error("context has a deadline with --timeout 0, want none")
	}
}

func TestCommandContext_MissingFlagFallsBackToDefault(t *testing.T) {
	// A command that never defined --timeout must not silently run unbounded.
	ctx, cancel := commandContext(&cobra.Command{})
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("context has no deadline when the flag is missing, want the default")
	}
	if remaining := time.Until(deadline); remaining <= defaultCommandTimeout-time.Minute || remaining > defaultCommandTimeout {
		t.Errorf("remaining = %v, want close to %v", remaining, defaultCommandTimeout)
	}
}

// With a 1ns budget the context is already expired when the first request
// starts, so the command must fail with a deadline error rather than
// proceed. No network access is needed for this to be deterministic.
func TestScan_TimeoutFlagBoundsTheCommand(t *testing.T) {
	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	content := `{"bomFormat":"CycloneDX","components":[{"type":"library","name":"foo","version":"1.0.0","purl":"pkg:pypi/foo@1.0.0"}]}`
	if err := os.WriteFile(sbomPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	root := NewRootCmd("test")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--sbom", sbomPath, "--no-kev", "--timeout", "1ns"})

	err := root.Execute()
	if err == nil {
		t.Fatal("Execute() with an already-expired --timeout should return an error, got nil")
	}
	if !strings.Contains(err.Error(), "deadline exceeded") {
		t.Errorf("error = %q, want it to mention the exceeded deadline", err.Error())
	}
}
