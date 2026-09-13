package main

import (
	"fmt"
	"os"
)

// version is set at build time via -ldflags. Defaults to "dev" for local builds.
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		os.Exit(1)
	}
}

func run() error {
	fmt.Printf("warden %s — software supply-chain security gate\n", version)
	return nil
}
