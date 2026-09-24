package piidetect

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
	spans, errs := c.Run(context.Background(), "text long enough for both spans")
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
	spans, errs := c.Run(context.Background(), "a@b.co")
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

// The guards validate what another engine claimed, in the forms that engine
// claims it: a printed (spaced) or lowercase IBAN, an IPv6 address or a CIDR
// block. Guards written for the regex floor's own shapes used to drop these.
func TestChainTypeGuardsKeepOtherEnginesForms(t *testing.T) {
	keep := []struct{ typ, value string }{
		{"IBAN", "DE89 3704 0044 0532 0130 00"},
		{"IBAN", "gb82west12345698765432"},
		{"IP", "2001:db8::1"},
		{"IP", "192.168.1.0/24"},
	}
	for _, k := range keep {
		text := "value: " + k.value + " end"
		c := &Chain{Timeout: time.Second, Detectors: []Detector{
			fakeDetector{name: "presidio", spans: []Span{{Start: 7, End: 7 + len(k.value), Type: k.typ, Confidence: 0.6, Detector: "presidio"}}},
		}}
		if spans, _ := c.Run(context.Background(), text); len(spans) != 1 {
			t.Errorf("%s %q dropped by its type guard", k.typ, k.value)
		}
	}
	text := "at 10:30:00 sharp"
	c := &Chain{Timeout: time.Second, Detectors: []Detector{
		fakeDetector{name: "presidio", spans: []Span{{Start: 3, End: 11, Type: "IP", Confidence: 0.6, Detector: "presidio"}}},
	}}
	if spans, _ := c.Run(context.Background(), text); len(spans) != 0 {
		t.Errorf("a clock time passed the IP guard: %+v", spans)
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

// A span outside the text must not panic a type guard, and must not merge
// with the floor's valid spans into a union Mask skips — which left the SSN
// below in the clear with no error at all.
func TestChainDropsOutOfRangeSpansAndReportsThem(t *testing.T) {
	text := "SSN 078-05-1120 here"
	c := &Chain{Timeout: time.Second, Detectors: []Detector{
		NewRegex(),
		fakeDetector{name: "buggy", spans: []Span{
			{Start: 2, End: 99, Type: "PERSON_NAME", Confidence: 0.5},
			{Start: 0, End: 99, Type: "CREDIT_CARD", Confidence: 0.5},
		}},
	}}
	clean, errs := c.Redact(context.Background(), text)
	if want := "SSN [SSN] here"; clean != want {
		t.Errorf("got %q, want %q", clean, want)
	}
	if len(errs) != 1 {
		t.Errorf("errs = %v, want the buggy engine's bad spans reported", errs)
	}
}

// The zero Timeout used to hand every engine an already-expired context, so a
// Chain literal without one could never reach its sidecar.
func TestChainZeroTimeoutUsesDefault(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[]`)
	}))
	defer stub.Close()
	c := &Chain{Detectors: []Detector{NewPresidio(stub.URL)}}
	if _, errs := c.Run(context.Background(), "hi"); len(errs) != 0 {
		t.Errorf("errs = %v", errs)
	}
}
