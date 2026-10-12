package cli

import "testing"

func TestStderrWarnf(t *testing.T) {
	cmd, stderr := newStderrCmd()

	stderrWarnf(cmd)("cache at %s unavailable", "/tmp/x")

	want := "warden: warning: cache at /tmp/x unavailable\n"
	if got := stderr.String(); got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
}
