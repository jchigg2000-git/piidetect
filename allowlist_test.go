package piidetect

import (
	"context"
	"testing"
	"time"
)

// stubDetector claims fixed spans, so these tests exercise the chain's own
// suppression rather than any engine's behaviour.
type stubDetector struct{ spans []Span }

func (s stubDetector) Name() string { return "stub" }
func (s stubDetector) Detect(context.Context, string) ([]Span, error) {
	return append([]Span(nil), s.spans...), nil
}

func chainWith(spans []Span, rules []PatternRule) *Chain {
	c := &Chain{Detectors: []Detector{stubDetector{spans}}, Timeout: time.Second}
	c.SetPatternPack(rules)
	return c
}

func typesOf(spans []Span) []string {
	out := make([]string, 0, len(spans))
	for _, s := range spans {
		out = append(out, s.Type)
	}
	return out
}

func TestAllowListSuppressesTheNamedTermOnly(t *testing.T) {
	text := "orbits: Spider-Man, Margaret Chen"
	spans := []Span{
		{Start: 8, End: 18, Type: "PERSON_NAME", Confidence: 0.85, Detector: "presidio"},
		{Start: 20, End: 33, Type: "PERSON_NAME", Confidence: 0.85, Detector: "presidio"},
	}
	rules := []PatternRule{{ID: "a1", Type: "PERSON_NAME", Kind: "allow_list", AllowList: []string{"Spider-Man"}}}

	got, errs := chainWith(spans, rules).Run(context.Background(), text)
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	if len(got) != 1 {
		t.Fatalf("got %d spans %v, want only the real name to survive", len(got), typesOf(got))
	}
	if s := text[got[0].Start:got[0].End]; s != "Margaret Chen" {
		t.Errorf("surviving span = %q, want %q", s, "Margaret Chen")
	}
}

// An allow term is scoped to the type it was approved for. Ruling "Mario" a
// false-positive PERSON_NAME must not also switch it off as, say, a deny-list
// term someone approved for another type.
func TestAllowListIsScopedToItsType(t *testing.T) {
	text := "Mario"
	rules := []PatternRule{{ID: "a1", Type: "PERSON_NAME", Kind: "allow_list", AllowList: []string{"Mario"}}}

	person := chainWith([]Span{{Start: 0, End: 5, Type: "PERSON_NAME"}}, rules)
	if got, _ := person.Run(context.Background(), text); len(got) != 0 {
		t.Errorf("PERSON_NAME should be suppressed, got %v", typesOf(got))
	}
	other := chainWith([]Span{{Start: 0, End: 5, Type: "ADDRESS"}}, rules)
	if got, _ := other.Run(context.Background(), text); len(got) != 1 {
		t.Errorf("ADDRESS must be unaffected by a PERSON_NAME allow term, got %v", typesOf(got))
	}
}

func TestAllowListMatchesCaseInsensitively(t *testing.T) {
	rules := []PatternRule{{ID: "a1", Type: "PERSON_NAME", Kind: "allow_list", AllowList: []string{"Pokemon"}}}
	c := chainWith([]Span{{Start: 0, End: 7, Type: "PERSON_NAME"}}, rules)
	if got, _ := c.Run(context.Background(), "POKEMON"); len(got) != 0 {
		t.Errorf("allow term should match regardless of case, got %v", typesOf(got))
	}
}

// The whole point of the primitive: it must beat any engine, the same way a
// typeGuard does, so a term ruled a false positive cannot come back because a
// different detector claimed it.
func TestAllowListOverrulesEveryEngine(t *testing.T) {
	text := "Dogman"
	c := &Chain{
		Detectors: []Detector{
			stubDetector{[]Span{{Start: 0, End: 6, Type: "PERSON_NAME", Detector: "presidio", Confidence: 0.85}}},
			stubDetector{[]Span{{Start: 0, End: 6, Type: "PERSON_NAME", Detector: "regex", Confidence: 0.99}}},
		},
		Timeout: time.Second,
	}
	c.SetPatternPack([]PatternRule{{ID: "a1", Type: "PERSON_NAME", Kind: "allow_list", AllowList: []string{"Dogman"}}})
	if got, _ := c.Run(context.Background(), text); len(got) != 0 {
		t.Errorf("a second engine re-claiming the term must not defeat suppression, got %v", typesOf(got))
	}
}

// Suppression is by term, not by region: allow-listing a term must not create
// a hole that hides real PII sitting next to it.
func TestAllowListDoesNotShieldNeighbouringSpans(t *testing.T) {
	text := "Mario lives at 123-45-6789"
	spans := []Span{
		{Start: 0, End: 5, Type: "PERSON_NAME"},
		{Start: 15, End: 26, Type: "SSN", Confidence: 0.9, Detector: "regex"},
	}
	rules := []PatternRule{{ID: "a1", Type: "PERSON_NAME", Kind: "allow_list", AllowList: []string{"Mario"}}}
	got, _ := chainWith(spans, rules).Run(context.Background(), text)
	if len(got) != 1 || got[0].Type != "SSN" {
		t.Errorf("SSN beside an allow-listed term must survive, got %v", typesOf(got))
	}
}

// An empty or absent pack must not suppress anything — the default is that
// every detection stands.
func TestNoPackSuppressesNothing(t *testing.T) {
	c := &Chain{Detectors: []Detector{stubDetector{[]Span{{Start: 0, End: 5, Type: "PERSON_NAME"}}}}, Timeout: time.Second}
	if got, _ := c.Run(context.Background(), "Mario"); len(got) != 1 {
		t.Errorf("unconfigured chain must not suppress, got %v", typesOf(got))
	}
	c.SetPatternPack([]PatternRule{{ID: "d1", Type: "PERSON_NAME", Kind: "deny_list", DenyList: []string{"x"}}})
	if got, _ := c.Run(context.Background(), "Mario"); len(got) != 1 {
		t.Errorf("a pack with no allow rules must not suppress, got %v", typesOf(got))
	}
}
