package piidetect

import (
	"strings"
)

// Mask replaces each span with its typed placeholder ([SSN], [EMAIL], …).
// Overlapping spans are merged first, as a Chain does, so no fragment of any
// claim survives; spans outside text are skipped. spans is not modified.
func Mask(text string, spans []Span) string {
	valid := make([]Span, 0, len(spans))
	for _, sp := range spans {
		if sp.within(text) {
			valid = append(valid, sp)
		}
	}
	if len(valid) == 0 {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	last := 0
	for _, sp := range Merge(valid) {
		b.WriteString(text[last:sp.Start])
		b.WriteByte('[')
		b.WriteString(sp.Type)
		b.WriteByte(']')
		last = sp.End
	}
	b.WriteString(text[last:])
	return b.String()
}
