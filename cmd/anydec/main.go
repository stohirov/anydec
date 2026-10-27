// Command anydec is a local-first decompiler for firmware and binaries from
// devices you own.
package main

import (
	"os"

	"github.com/stohirov/decompile-anything/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
