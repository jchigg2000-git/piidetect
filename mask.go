package piidetect

import (
	"sort"
)

// Mask replaces each span with its typed placeholder ([SSN], [EMAIL], …),
// rewriting right-to-left so earlier offsets stay valid. Spans must be
// non-overlapping (detect.Merge guarantees it).
func Mask(text string, spans []Span) string {
	if len(spans) == 0 {
		return text
	}
	sorted := make([]Span, len(spans))
	copy(sorted, spans)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Start > sorted[j].Start })
	for _, sp := range sorted {
		if sp.Start < 0 || sp.End > len(text) || sp.Start >= sp.End {
			continue
		}
		text = text[:sp.Start] + "[" + sp.Type + "]" + text[sp.End:]
	}
	return text
}
