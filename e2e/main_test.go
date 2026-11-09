//go:build e2e

// Package e2e runs the real warden binary, as a subprocess, against
// in-process mock versions of the services it talks to (OSV, deps.dev,
// and CISA's KEV catalog). Run it with: make e2e
package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// wardenBin is the warden binary, built once for the whole run.
var wardenBin string

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	dir, err := os.MkdirTemp("", "warden-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create temp dir:", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()

	wardenBin = filepath.Join(dir, "warden")
	build := exec.Command("go", "build", "-o", wardenBin, "../cmd/warden")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build warden:", err)
		return 1
	}

	return m.Run()
}
