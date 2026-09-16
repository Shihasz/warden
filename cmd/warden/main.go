package main

import (
	"fmt"
	"os"

	"github.com/Shihasz/warden/internal/cli"
)

// version is set at build time via -ldflags. Defaults to "dev" for local builds.
var version = "dev"

func main() {
	if err := cli.NewRootCmd(version).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		os.Exit(1)
	}
}
