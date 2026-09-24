package piidetect

import (
	"strings"
	"testing"
)

func TestMaskReplacesSpans(t *testing.T) {
	text := "SSN 123-45-6789 email a@b.co done"
	spans := []Span{
		{Start: 4, End: 15, Type: "SSN"},
		{Start: 22, End: 28, Type: "EMAIL"},
	}
	got := Mask(text, spans)
	want := "SSN [SSN] email [EMAIL] done"
	if got != want {
		t.Errorf("Mask = %q, want %q", got, want)
	}
}

func TestMaskNoSpansIsIdentity(t *testing.T) {
	if got := Mask("untouched", nil); got != "untouched" {
		t.Errorf("Mask = %q", got)
	}
}

func TestMaskIgnoresOutOfRangeSpans(t *testing.T) {
	if got := Mask("abc", []Span{{Start: 1, End: 99, Type: "X"}}); got != "abc" {
		t.Errorf("Mask = %q, want untouched on invalid span", got)
	}
}

// Overlapping spans used to be rewritten one after the other, so the second
// replacement read offsets the first had moved and left "ABCDE" in the clear.
func TestMaskOverlappingSpansLeaveNothing(t *testing.T) {
	got := Mask("0123456789ABCDEFGHIJKLMNOP", []Span{
		{Start: 10, End: 20, Type: "A", Confidence: 0.9},
		{Start: 15, End: 25, Type: "B", Confidence: 0.5},
	})
	if want := "0123456789[A]P"; got != want {
		t.Errorf("Mask = %q, want %q", got, want)
	}
}

// Mask used to rebuild the whole string once per span: 20k spans in 380KB
// allocated 7.9GB. It must stay a single pass.
func TestMaskIsOnePass(t *testing.T) {
	text := strings.Repeat("mail a@b.co ", 1000)
	var spans []Span
	for i := 0; i < 1000; i++ {
		spans = append(spans, Span{Start: i*12 + 5, End: i*12 + 11, Type: "EMAIL"})
	}
	if n := testing.AllocsPerRun(5, func() { Mask(text, spans) }); n > 20 {
		t.Errorf("Mask made %.0f allocations for 1000 spans, want a handful", n)
	}
}
