package engine

import (
	"regexp"
	"strings"

	"github.com/stohirov/decompile-anything/internal/analysis"
	"github.com/stohirov/decompile-anything/internal/ir"
	"github.com/stohirov/decompile-anything/internal/lift"
)

// Function is a discovered function with its control-flow graph in IR.
type Function = ir.Function

// Block is a basic block of a Function's CFG.
type Block = ir.Block

// Analysis is what the engine knows about a Program's code.
type Analysis struct {
	Program   *Program
	Arch      *ir.Arch
	Functions []*Function // sorted by entry address
	lifter    *lift.Lifter
}

// Analyze discovers the functions of p and builds their CFGs, resolving
// jump tables. With sweep set it also looks for functions in code that no
// known function reaches, as stripped binaries need.
func Analyze(p *Program, sweep bool) (*Analysis, error) {
	d, err := NewDisassembler(p)
	if err != nil {
		return nil, err
	}
	l := lift.New(p.Language, d.dec)
	opt := analysis.Options{Alignment: max(d.Spec().Alignment, 1), Sweep: sweep}
	if sweep {
		opt.Prologue = prologue(p.Language)
	}
	return &Analysis{
		Program:   p,
		Arch:      l.Arch(),
		Functions: analysis.Discover(p, l, opt),
		lifter:    l,
	}, nil
}

// Function returns the function with the given entry address or name.
func (a *Analysis) Function(entry uint64, name string) *Function {
	for _, fn := range a.Functions {
		if (name == "" && fn.Entry == entry) || (name != "" && fn.Name == name) {
			return fn
		}
	}
	return nil
}

// Register returns the varnode of the named register.
func (a *Analysis) Register(name string) (ir.Varnode, bool) {
	return a.lifter.Register(name)
}

// prologues match the text of instructions that typically open a function,
// keyed by SLEIGH processor name.
var prologues = map[string]*regexp.Regexp{
	"ARM":     regexp.MustCompile(`^(push|stmdb sp!,)\s?\{.*lr\}$`),
	"AARCH64": regexp.MustCompile(`^(stp x29,x30,\[sp,#-|paciasp$|bti c$)`),
	"x86":     regexp.MustCompile(`^(PUSH RBP|PUSH EBP|ENDBR64|ENDBR32)$`),
	"MIPS":    regexp.MustCompile(`^addiu sp,sp,-`),
}

func prologue(language string) func(*ir.Insn) bool {
	proc, _, _ := strings.Cut(language, ":")
	re := prologues[proc]
	if re == nil {
		return nil
	}
	return func(in *ir.Insn) bool { return re.MatchString(in.Text) }
}
