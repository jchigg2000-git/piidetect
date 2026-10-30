package piidetect

import (
	"strings"
)

// MaskFunc returns the replacement for one span. sp is the merged span, so
// sp.Type is the type Merge gave it: that of its highest-confidence claim; on
// a tie, the claim that starts first, then the longer, then the lower Type in
// byte order. value is text[sp.Start:sp.End], the original characters the
// replacement stands for. A MaskFunc that returns a function of value — a
// hash, a lookup — can leak it; the default [TYPE] cannot.
type MaskFunc func(sp Span, value string) string

// Mask replaces each span with its typed placeholder ([SSN], [EMAIL], …).
// Overlapping spans are merged first, as a Chain does, so no fragment of any
// claim survives; spans outside text are skipped. spans is not modified.
func Mask(text string, spans []Span) string {
	return mask(text, spans, nil)
}

// MaskWith is Mask with the replacement chosen by f, called once per merged
// span in text order. Merging, skipping and the single pass are Mask's; a nil
// f is Mask. See Chain.RedactWith for consistent pseudonymization.
func MaskWith(text string, spans []Span, f MaskFunc) string {
	return mask(text, spans, f)
}

func mask(text string, spans []Span, f MaskFunc) string {
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
	if f == nil {
		// The default path, kept free of a call per span.
		for _, sp := range Merge(valid) {
			b.WriteString(text[last:sp.Start])
			b.WriteByte('[')
			b.WriteString(sp.Type)
			b.WriteByte(']')
			last = sp.End
		}
	} else {
		for _, sp := range Merge(valid) {
			b.WriteString(text[last:sp.Start])
			b.WriteString(f(sp, text[sp.Start:sp.End]))
			last = sp.End
		}
	}
	b.WriteString(text[last:])
	return b.String()
}
