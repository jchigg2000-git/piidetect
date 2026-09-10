package piidetect

import (
	"testing"
)

func TestMaskReplacesSpansRightToLeft(t *testing.T) {
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
