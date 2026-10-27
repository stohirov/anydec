// Package emit renders structured functions as C-like text with address
// comments, a JSON AST for tools, and an HTML view linking each line to its
// assembly. Readability passes on the C AST (for-loop folding, temporary
// collapsing, evidence-based renaming, constant printing) run here.
package emit
