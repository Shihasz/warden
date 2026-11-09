//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// lab is one isolated e2e environment: a project directory, a private
// HOME (so the KEV cache never touches the developer's real one), and the
// three mock data sources warden is pointed at.
type lab struct {
	dir string
	// Env adds or overrides environment variables for warden runs, on top
	// of the defaults that point it at the mocks.
	Env map[string]string

	OSV     *mockOSV
	DepsDev *mockDepsDev
	KEV     *mockKEV
}

func newLab(t *testing.T) *lab {
	t.Helper()
	return &lab{
		dir:     t.TempDir(),
		Env:     map[string]string{},
		OSV:     newMockOSV(t),
		DepsDev: newMockDepsDev(t),
		KEV:     newMockKEV(t),
	}
}

// path resolves a file name inside the lab's project directory.
func (l *lab) path(name string) string { return filepath.Join(l.dir, name) }

// useProject copies a fixture project from testdata/projects into the lab.
func (l *lab) useProject(t *testing.T, name string) {
	t.Helper()
	copyTree(t, filepath.Join("testdata", "projects", name), l.dir)
}

// copyRepoFile copies a file from elsewhere in the repository (path
// relative to the e2e directory) into the lab under a new name. Scenarios
// use it to run against the repository's real policy files.
func (l *lab) copyRepoFile(t *testing.T, src, dstName string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(l.path(dstName), data, 0o644); err != nil {
		t.Fatalf("write %s: %v", dstName, err)
	}
}

// readJSON decodes a JSON file warden wrote into the lab.
func (l *lab) readJSON(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(l.path(name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s is not the expected JSON: %v\n%s", name, err, data)
	}
}

func (l *lab) environ() []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + filepath.Join(l.dir, ".home"),
		"WARDEN_OSV_URL=" + l.OSV.URL(),
		"WARDEN_DEPSDEV_URL=" + l.DepsDev.URL(),
		"WARDEN_KEV_URL=" + l.KEV.URL(),
	}
	// Later entries win over earlier duplicates.
	for k, v := range l.Env {
		env = append(env, k+"="+v)
	}
	return env
}

// result is the outcome of one warden invocation.
type result struct {
	stdout string
	stderr string
	exit   int
}

// run executes the real warden binary inside the lab, in a clean
// environment, with a hard time limit so a hang fails the test instead of
// stalling the run.
func (l *lab) run(t *testing.T, args ...string) result {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, wardenBin, args...)
	cmd.Dir = l.dir
	cmd.Env = l.environ()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	res := result{}
	err := cmd.Run()
	res.stdout, res.stderr = stdout.String(), stderr.String()

	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		res.exit = exitErr.ExitCode()
	default:
		t.Fatalf("running warden %v: %v", args, err)
	}
	return res
}

func (r result) requireExit(t *testing.T, want int) {
	t.Helper()
	if r.exit != want {
		t.Fatalf("exit code = %d, want %d\n--- stdout ---\n%s\n--- stderr ---\n%s", r.exit, want, r.stdout, r.stderr)
	}
}

// decode parses the command's stdout as JSON.
func (r result) decode(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(r.stdout), v); err != nil {
		t.Fatalf("stdout is not the expected JSON: %v\n--- stdout ---\n%s\n--- stderr ---\n%s", err, r.stdout, r.stderr)
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copy %s: %v", src, err)
	}
}
