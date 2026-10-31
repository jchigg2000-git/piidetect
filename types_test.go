package piidetect

import (
	"context"
	"strings"
	"testing"
)

// A disabled type is gone from every detector's output, and the floor does not
// scan for it; the other types are untouched.
func TestChainDisable(t *testing.T) {
	ctx := context.Background()
	text := "visit 03/14/2026, ssn 078-05-1120"
	c := New()
	c.Detectors = append(c.Detectors, stubDetector{[]Span{{Start: 6, End: 16, Type: TypeDOB, Confidence: 0.9}}})
	c.Disable = []string{TypeDOB}
	clean, errs := c.Redact(ctx, text)
	if errs != nil {
		t.Fatalf("errors: %v", errs)
	}
	if want := "visit 03/14/2026, ssn [SSN]"; clean != want {
		t.Errorf("got  %q\nwant %q", clean, want)
	}
	for _, rec := range *NewRegex().without(map[string]bool{TypeDOB: true}).compiled.Load() {
		if rec.typ == TypeDOB {
			t.Error("a disabled type's recognizer is still scanned")
		}
	}
}

// One SetPatternPack on the chain reaches its Regex and its Presidio, and a
// rule the Regex rejects comes back from every Run until a good pack replaces it.
func TestChainSetPatternPackForwards(t *testing.T) {
	ctx := context.Background()
	p := NewPresidio("http://127.0.0.1:0")
	rx := NewRegex()
	c := &Chain{Detectors: []Detector{rx, p}}
	pack := []PatternRule{{ID: "emp-id", Type: "EMPLOYEE_ID", Regex: `\bEMP\d{6}\b`}}
	c.SetPatternPack(pack)
	if spans, _ := rx.Detect(ctx, "badge EMP123456"); len(spans) != 1 || spans[0].Type != "EMPLOYEE_ID" {
		t.Errorf("the chain's pack did not reach its Regex: %v", spans)
	}
	if got := len(p.pack.Load().rules); got != 1 {
		t.Errorf("the chain's pack did not reach its Presidio: %d rules", got)
	}

	c = &Chain{Detectors: []Detector{rx}}
	c.SetPatternPack([]PatternRule{{ID: "bad", Type: "X", Regex: "("}})
	for range 2 {
		if _, errs := c.Run(ctx, "badge EMP123456"); errs == nil || !strings.Contains(errs.Error(), "pattern bad") {
			t.Errorf("a rejected rule must surface on Run, got %v", errs)
		}
	}
	c.SetPatternPack(pack)
	if _, errs := c.Run(ctx, "badge EMP123456"); errs != nil {
		t.Errorf("a good pack must clear the error, got %v", errs)
	}
}

// The pre-forwarding README configured a Regex's rules and the chain's allow
// list in two calls. The allow-list-only call must not wipe the Regex's rules,
// or the values they caught would go out with no error.
func TestChainAllowListPackKeepsDetectorRules(t *testing.T) {
	regex := NewRegex()
	if err := regex.SetPatternPack([]PatternRule{{ID: "emp", Type: "EMPLOYEE_ID", Regex: `\bEMP\d{6}\b`, Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	c := &Chain{Detectors: []Detector{regex}}
	c.SetPatternPack([]PatternRule{{ID: "ok", Type: TypeEmail, Kind: "allow_list", AllowList: []string{"support@example.com"}}})
	got, errs := c.Redact(context.Background(), "EMP123456 wrote support@example.com")
	if errs != nil || got != "[EMPLOYEE_ID] wrote support@example.com" {
		t.Errorf("Redact = %q, %v", got, errs)
	}
}
