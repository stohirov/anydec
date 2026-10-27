package sleigh

// UserOps returns the names of the spec's CALLOTHER operations, by index.
func (s *Spec) UserOps() []string {
	return append([]string(nil), s.userOps...)
}
