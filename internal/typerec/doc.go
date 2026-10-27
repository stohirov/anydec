// Package typerec recovers types by constraint inference over SSA values,
// solved on a lattice from unknown to concrete types (the TIE/Retypd
// approach), then recovers structs and arrays from access patterns. External
// facts seed it, highest confidence first: DWARF, bundled library prototypes,
// library function matching, and format strings. User overrides are hard
// constraints.
package typerec
