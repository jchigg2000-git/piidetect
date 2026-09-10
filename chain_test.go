package piidetect

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeDetector struct {
	name  string
	spans []Span
	err   error
}

func (f fakeDetector) Name() string { return f.name }
func (f fakeDetector) Detect(context.Context, string) ([]Span, error) {
	return f.spans, f.err
}

func TestChainMergesOverlapsHigherConfidenceWins(t *testing.T) {
	c := &Chain{Timeout: time.Second, Detectors: []Detector{
		fakeDetector{name: "a", spans: []Span{{Start: 10, End: 21, Type: "SSN", Confidence: 0.9, Detector: "a"}}},
		fakeDetector{name: "b", spans: []Span{{Start: 8, End: 21, Type: "US_SSN_CTX", Confidence: 0.95, Detector: "b"}}},
	}}
	spans, errs := c.Run(context.Background(), "irrelevant")
	if len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
	if len(spans) != 1 {
		t.Fatalf("spans = %+v, want 1 merged", spans)
	}
	sp := spans[0]
	if sp.Start != 8 || sp.End != 21 {
		t.Errorf("extent = [%d,%d), want union [8,21)", sp.Start, sp.End)
	}
	if sp.Type != "US_SSN_CTX" || sp.Detector != "b" {
		t.Errorf("winner = %s/%s, want higher-confidence b/US_SSN_CTX", sp.Detector, sp.Type)
	}
}

func TestChainCollectsErrorsAndKeepsGoodSpans(t *testing.T) {
	c := &Chain{Timeout: time.Second, Detectors: []Detector{
		fakeDetector{name: "regex", spans: []Span{{Start: 0, End: 5, Type: "EMAIL", Confidence: 0.9}}},
		fakeDetector{name: "presidio", err: errors.New("connection refused")},
	}}
	spans, errs := c.Run(context.Background(), "x")
	if len(spans) != 1 {
		t.Errorf("good detector's spans lost: %+v", spans)
	}
	if len(errs) != 1 {
		t.Errorf("errs = %v, want the presidio failure surfaced", errs)
	}
}

// Any engine claiming SSN glued to a hyphenated identifier is overruled by
// the chain-level type guard — the ORD-123-45-6789 trap, engine-independent.
func TestChainTypeGuardsOverruleAnyEngine(t *testing.T) {
	text := "Where is order ORD-483-92-5714? It shipped."
	c := &Chain{Timeout: time.Second, Detectors: []Detector{
		fakeDetector{name: "presidio", spans: []Span{{Start: 19, End: 30, Type: "SSN", Confidence: 0.5, Detector: "presidio"}}},
	}}
	spans, _ := c.Run(context.Background(), text)
	if len(spans) != 0 {
		t.Errorf("hyphen-adjacent SSN claim survived the type guard: %+v", spans)
	}
}

func TestMergeKeepsDisjointSpans(t *testing.T) {
	spans := Merge([]Span{
		{Start: 20, End: 30, Type: "EMAIL"},
		{Start: 0, End: 10, Type: "SSN"},
	})
	if len(spans) != 2 || spans[0].Start != 0 || spans[1].Start != 20 {
		t.Errorf("merge broke disjoint spans: %+v", spans)
	}
}
