// Package emit renders functions in SSA form as C. It leaves SSA (phis
// become variables assigned on the edges into their blocks), inlines
// values used once, gives every value a C type from its size and from the
// float operations that touch it, and prints the structured control flow
// from package structure. A whole program renders as one translation unit
// that compiles for the program's own target, with the data the code
// references. A JSON AST and an HTML view come later.
package emit
