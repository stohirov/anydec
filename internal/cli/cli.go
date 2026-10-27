// Package cli implements the anydec command line on top of package engine.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/stohirov/decompile-anything/engine"
	"github.com/stohirov/decompile-anything/internal/intake"
)

type command struct {
	name    string
	usage   string
	summary string
	run     func(args []string, stdout io.Writer) error
}

var commands = []command{
	{"identify", "identify <file>", "classify a file and report high-entropy regions", runIdentify},
	{"unpack", "unpack <firmware> -o <dir>", "recursively extract a firmware image", runUnpack},
	{"open", "open <binary> --project <file>", "load a binary into a project database", runOpen},
	{"funcs", "funcs <project> [--filter <text>]", "list discovered functions", runFuncs},
	{"decompile", "decompile <project> <addr> [--format c|json|html]", "decompile one function", runDecompile},
	{"raw", "raw <dump> --isa <spec> [--base auto|<addr>] [--svd <file>]", "load a headerless flash dump", runRaw},
	{"serve", "serve <project> [--mcp]", "serve the engine API or an MCP server", runServe},
	{"version", "version", "print the version", runVersion},
}

// Run executes the command line in args (without the program name) and
// returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage(stdout)
		return 0
	}
	for _, c := range commands {
		if c.name != args[0] {
			continue
		}
		err := c.run(args[1:], stdout)
		switch {
		case err == nil:
			return 0
		case errors.Is(err, flag.ErrHelp):
			fmt.Fprintf(stdout, "usage: anydec %s\n", c.usage)
			return 0
		case errors.Is(err, errUsage):
			fmt.Fprintf(stderr, "usage: anydec %s\n", c.usage)
			return 2
		default:
			fmt.Fprintf(stderr, "anydec %s: %v\n", c.name, err)
			return 1
		}
	}
	fmt.Fprintf(stderr, "anydec: unknown command %q\n\n", args[0])
	printUsage(stderr)
	return 2
}

var errUsage = errors.New("usage")

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "anydec: a local-first decompiler for firmware and binaries you own")
	fmt.Fprintln(w, "\nUsage:")
	for _, c := range commands {
		fmt.Fprintf(w, "  anydec %-60s %s\n", c.usage, c.summary)
	}
}

// parse parses flags that may appear before, between or after positional
// arguments, and checks the positional count.
func parse(fs *flag.FlagSet, args []string, positional int) ([]string, error) {
	fs.SetOutput(io.Discard)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	if len(pos) != positional {
		return nil, errUsage
	}
	return pos, nil
}

func runIdentify(args []string, stdout io.Writer) error {
	pos, err := parse(flag.NewFlagSet("identify", flag.ContinueOnError), args, 1)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	r := engine.Identify(data)
	fmt.Fprintf(stdout, "kind: %s\n", r.Kind)
	fmt.Fprintf(stdout, "size: %d bytes, %d blocks of %d\n", len(data), len(r.Entropy), intake.BlockSize)
	if len(r.HighEntropyBlocks) == 0 {
		fmt.Fprintln(stdout, "high-entropy blocks: none")
		return nil
	}
	fmt.Fprintf(stdout, "high-entropy blocks (>= %.1f bits/byte, likely compressed or encrypted):\n", intake.HighEntropy)
	for _, i := range r.HighEntropyBlocks {
		fmt.Fprintf(stdout, "  %#08x  %.3f\n", i*intake.BlockSize, r.Entropy[i])
	}
	return nil
}

func runUnpack(args []string, _ io.Writer) error {
	fs := flag.NewFlagSet("unpack", flag.ContinueOnError)
	out := fs.String("o", "", "output directory")
	if _, err := parse(fs, args, 1); err != nil {
		return err
	}
	if *out == "" {
		return errUsage
	}
	return engine.ErrNotImplemented
}

func runOpen(args []string, _ io.Writer) error {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	project := fs.String("project", "", "project database to create or update")
	if _, err := parse(fs, args, 1); err != nil {
		return err
	}
	if *project == "" {
		return errUsage
	}
	return engine.ErrNotImplemented
}

func runFuncs(args []string, _ io.Writer) error {
	fs := flag.NewFlagSet("funcs", flag.ContinueOnError)
	fs.String("filter", "", "only list functions whose name contains this text")
	if _, err := parse(fs, args, 1); err != nil {
		return err
	}
	return engine.ErrNotImplemented
}

func runDecompile(args []string, _ io.Writer) error {
	fs := flag.NewFlagSet("decompile", flag.ContinueOnError)
	format := fs.String("format", "c", "output format: c, json or html")
	pos, err := parse(fs, args, 2)
	if err != nil {
		return err
	}
	if _, err := strconv.ParseUint(pos[1], 0, 64); err != nil {
		return fmt.Errorf("invalid address %q", pos[1])
	}
	switch *format {
	case "c", "json", "html":
	default:
		return fmt.Errorf("unknown format %q", *format)
	}
	return engine.ErrNotImplemented
}

func runRaw(args []string, _ io.Writer) error {
	fs := flag.NewFlagSet("raw", flag.ContinueOnError)
	isa := fs.String("isa", "", "SLEIGH language id, e.g. ARM:LE:32:Cortex")
	base := fs.String("base", "auto", "load address, or auto to infer it")
	fs.String("svd", "", "CMSIS-SVD file naming peripheral registers")
	if _, err := parse(fs, args, 1); err != nil {
		return err
	}
	if *isa == "" {
		return errUsage
	}
	if *base != "auto" {
		if _, err := strconv.ParseUint(*base, 0, 64); err != nil {
			return fmt.Errorf("invalid base address %q", *base)
		}
	}
	return engine.ErrNotImplemented
}

func runServe(args []string, _ io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.Bool("mcp", false, "serve the MCP protocol for local or hosted agents")
	if _, err := parse(fs, args, 1); err != nil {
		return err
	}
	return engine.ErrNotImplemented
}

func runVersion(args []string, stdout io.Writer) error {
	if _, err := parse(flag.NewFlagSet("version", flag.ContinueOnError), args, 0); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "anydec %s\n", engine.Version)
	return nil
}
