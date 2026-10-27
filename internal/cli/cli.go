// Package cli implements the anydec command line on top of package engine.
package cli

import (
	"bufio"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/stohirov/decompile-anything/engine"
	"github.com/stohirov/decompile-anything/internal/intake"
	"github.com/stohirov/decompile-anything/internal/loader"
)

type command struct {
	name    string
	usage   string
	summary string
	run     func(args []string, stdout io.Writer) error
}

var commands = []command{
	{"identify", "identify <file>", "classify a file and report high-entropy regions", runIdentify},
	{"disasm", "disasm <binary> [--func <name|addr>]", "disassemble code with the SLEIGH decoder", runDisasm},
	{"unpack", "unpack <firmware> -o <dir>", "recursively extract a firmware image", runUnpack},
	{"ir", "ir <binary|project> --func <name|addr> [--ssa]", "print a function's control-flow graph in IR, or its SSA form", runIR},
	{"open", "open <binary> --project <file> [--sweep=false]", "analyze a binary into a new project database", runOpen},
	{"funcs", "funcs <binary|project> [--filter <text>] [--sweep=false]", "list discovered functions", runFuncs},
	{"decompile", "decompile <binary|project> [<name|addr>] [--addrs] [--format c|json|html]", "decompile a function, or all of them as one C file", runDecompile},
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

func runDisasm(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("disasm", flag.ContinueOnError)
	fn := fs.String("func", "", "only disassemble the function with this name or address")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	prog, err := engine.Load(data)
	if err != nil {
		return err
	}
	d, err := engine.NewDisassembler(prog)
	if err != nil {
		return err
	}
	ranges, err := disasmRanges(prog, *fn)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(stdout)
	defer w.Flush()
	for _, r := range ranges {
		fmt.Fprintf(w, "\n%s:\n", r.name)
		err := d.Range(r.start, r.end, func(l engine.Line) {
			if s, ok := prog.Symbol(l.Addr); ok && s.Kind == loader.SymFunction {
				fmt.Fprintf(w, "\n%08x <%s>:\n", l.Addr, s.Name)
			}
			fmt.Fprintf(w, "%8x: %-12s %s\n", l.Addr, hex.EncodeToString(l.Bytes), l.Text())
		})
		if err != nil {
			return err
		}
	}
	return nil
}

type addrRange struct {
	name       string
	start, end uint64
}

// disasmRanges returns the executable segments, or the one function fn
// names by symbol or address.
func disasmRanges(prog *engine.Program, fn string) ([]addrRange, error) {
	if fn == "" {
		var out []addrRange
		for _, s := range prog.Segments {
			if s.Perm&loader.PermX != 0 {
				out = append(out, addrRange{s.Name, s.Addr, s.End()})
			}
		}
		return out, nil
	}
	sym, ok := prog.Lookup(fn)
	if !ok {
		addr, err := strconv.ParseUint(fn, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("no function %q", fn)
		}
		if sym, ok = prog.Symbol(addr); !ok {
			sym = loader.Symbol{Name: fn, Addr: addr}
		}
	}
	end := sym.Addr + sym.Size
	if sym.Size == 0 {
		seg := prog.Segment(sym.Addr)
		if seg == nil {
			return nil, fmt.Errorf("address %#x is not mapped", sym.Addr)
		}
		end = seg.End()
	}
	return []addrRange{{sym.Name, sym.Addr, end}}, nil
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

func runOpen(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	project := fs.String("project", "", "project database to create")
	sweep := fs.Bool("sweep", true, "also look for functions no call reaches, as stripped binaries need")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if *project == "" {
		return errUsage
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	p, err := engine.CreateProject(*project, pos[0], data, *sweep)
	if err != nil {
		return err
	}
	defer p.Close()
	fns, err := p.Functions()
	if err != nil {
		return err
	}
	warn := 0
	for _, f := range fns {
		if f.Status != "decompiled" {
			warn++
		}
	}
	fmt.Fprintf(stdout, "%s: %d functions (%d with warnings) from %s\n", *project, len(fns), warn, pos[0])
	return nil
}

// analyze opens the project or analyzes the binary at path. The returned
// function releases the project.
func analyze(path string, sweep bool) (*engine.Analysis, func(), error) {
	if engine.IsProject(path) {
		p, err := engine.OpenProject(path)
		if err != nil {
			return nil, nil, err
		}
		return p.Analysis, func() { p.Close() }, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	prog, err := engine.Load(data)
	if err != nil {
		return nil, nil, err
	}
	a, err := engine.Analyze(prog, sweep)
	return a, func() {}, err
}

// findFunction looks a function up by name or entry address.
func findFunction(a *engine.Analysis, name string) (*engine.Function, error) {
	if fn := a.Function(0, name); fn != nil {
		return fn, nil
	}
	addr, err := strconv.ParseUint(name, 0, 64)
	if fn := a.Function(addr, ""); err == nil && fn != nil {
		return fn, nil
	}
	return nil, fmt.Errorf("no function %q", name)
}

func runFuncs(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("funcs", flag.ContinueOnError)
	filter := fs.String("filter", "", "only list functions whose name contains this text")
	sweep := fs.Bool("sweep", true, "also look for functions no call reaches, as stripped binaries need")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	a, done, err := analyze(pos[0], *sweep)
	if err != nil {
		return err
	}
	defer done()
	w := bufio.NewWriter(stdout)
	defer w.Flush()
	fmt.Fprintf(w, "%-10s %6s %6s %6s %5s  %s\n", "entry", "bytes", "insns", "blocks", "calls", "name")
	for _, fn := range a.Functions {
		if !strings.Contains(fn.Name, *filter) {
			continue
		}
		var size uint64
		for _, in := range fn.Insns {
			size += uint64(in.Length)
		}
		var notes []string
		if n := len(fn.JumpTables); n > 0 {
			notes = append(notes, fmt.Sprintf("%d jump table(s)", n))
		}
		if n := len(fn.Unresolved); n > 0 {
			notes = append(notes, fmt.Sprintf("%d unresolved indirect jump(s)", n))
		}
		if n := len(fn.Warnings); n > 0 {
			notes = append(notes, fmt.Sprintf("%d warning(s)", n))
		}
		note := ""
		if len(notes) > 0 {
			note = "  (" + strings.Join(notes, ", ") + ")"
		}
		fmt.Fprintf(w, "%#-10x %6d %6d %6d %5d  %s%s\n", fn.Entry, size, len(fn.Insns), len(fn.Blocks), len(fn.Calls), fn.Name, note)
	}
	return nil
}

func runIR(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("ir", flag.ContinueOnError)
	name := fs.String("func", "", "function name or entry address")
	ssaForm := fs.Bool("ssa", false, "print the SSA form after simplification and prototype analysis")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if *name == "" {
		return errUsage
	}
	a, done, err := analyze(pos[0], true)
	if err != nil {
		return err
	}
	defer done()
	fn, err := findFunction(a, *name)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(stdout)
	defer w.Flush()
	if *ssaForm {
		f, err := a.SSA(fn)
		if err != nil {
			return err
		}
		fmt.Fprint(w, f)
		return nil
	}
	writeIR(w, a, fn)
	return nil
}

// writeIR prints fn's blocks with each instruction's text above its ops.
func writeIR(w io.Writer, a *engine.Analysis, fn *engine.Function) {
	fmt.Fprintf(w, "%s at %#x: %d blocks, %d instructions\n", fn.Name, fn.Entry, len(fn.Blocks), len(fn.Insns))
	for _, jt := range fn.JumpTables {
		targets := map[uint64][]string{}
		var order []uint64
		for _, c := range jt.Cases {
			if targets[c.Target] == nil {
				order = append(order, c.Target)
			}
			targets[c.Target] = append(targets[c.Target], strconv.FormatInt(c.Value, 10))
		}
		fmt.Fprintf(w, "jump table at %#x:", jt.Addr)
		for _, t := range order {
			vals := targets[t]
			if len(vals) > 4 {
				vals = append(vals[:3], fmt.Sprintf("... (%d values)", len(targets[t])))
			}
			fmt.Fprintf(w, " %s->%#x", strings.Join(vals, ","), t)
		}
		fmt.Fprintln(w)
	}
	for _, u := range fn.Unresolved {
		fmt.Fprintf(w, "unresolved indirect jump at %#x\n", u)
	}
	for _, warn := range fn.Warnings {
		fmt.Fprintf(w, "warning: %s\n", warn)
	}
	index := map[*engine.Block]int{}
	for i, b := range fn.Blocks {
		index[b] = i
	}
	text := map[uint64]string{}
	for _, in := range fn.Insns {
		text[in.Addr] = in.Text
	}
	for i, b := range fn.Blocks {
		var succ []string
		for _, s := range b.Succ {
			succ = append(succ, fmt.Sprintf("b%d", index[s]))
		}
		fmt.Fprintf(w, "\nb%d at %#x", i, b.Start)
		if len(succ) > 0 {
			fmt.Fprintf(w, " -> %s", strings.Join(succ, " "))
		}
		fmt.Fprintln(w)
		origin := ^uint64(0)
		for _, op := range b.Ops {
			if op.Origin != origin {
				origin = op.Origin
				fmt.Fprintf(w, "  %8x: %s\n", origin, text[origin])
			}
			fmt.Fprintf(w, "            %s\n", a.Arch.FormatOp(op))
		}
	}
}

func runDecompile(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("decompile", flag.ContinueOnError)
	format := fs.String("format", "c", "output format: c, json or html")
	addrs := fs.Bool("addrs", false, "comment each statement with its instruction address")
	sweep := fs.Bool("sweep", true, "for binaries, also look for functions no call reaches")
	fs.SetOutput(io.Discard)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) < 1 || len(pos) > 2 {
		return errUsage
	}
	switch *format {
	case "c":
	case "json", "html":
		return fmt.Errorf("format %s: %w", *format, engine.ErrNotImplemented)
	default:
		return fmt.Errorf("unknown format %q", *format)
	}
	a, done, err := analyze(pos[0], *sweep)
	if err != nil {
		return err
	}
	defer done()
	var out string
	if len(pos) == 1 {
		out, err = a.Source(*addrs)
	} else {
		fn, ferr := findFunction(a, pos[1])
		if ferr != nil {
			return ferr
		}
		out, err = a.Decompile(fn, *addrs)
	}
	if err != nil {
		return err
	}
	_, err = io.WriteString(stdout, out)
	return err
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
