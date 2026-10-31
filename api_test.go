package piidetect

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// The quickstart in the README is this test. If it stops compiling or the
// output changes, the README is wrong and CI says so.
func TestReadmeQuickstart(t *testing.T) {
	clean, errs := New().Redact(context.Background(),
		"Member 078-05-1120 paid with 4111 1111 1111 1111; reach her at jane.doe@example.org.")
	if errs != nil {
		t.Fatalf("unexpected errors: %v", errs)
	}
	want := "Member [SSN] paid with [CREDIT_CARD]; reach her at [EMAIL]."
	if clean != want {
		t.Fatalf("got  %q\nwant %q", clean, want)
	}
}

// The order-number trap: a hyphen-adjacent SSN-shaped run is an identifier,
// not an SSN, and a 13-digit run that fails Luhn is not a card.
func TestGuardsRejectLookalikes(t *testing.T) {
	clean, _ := New().Redact(context.Background(),
		"Order ORD-123-45-6789 shipped; ref 4111111111111112 is not a card.")
	if strings.Contains(clean, "[SSN]") {
		t.Errorf("hyphen-adjacent identifier claimed as SSN: %q", clean)
	}
	if strings.Contains(clean, "[CREDIT_CARD]") {
		t.Errorf("Luhn-invalid run claimed as card: %q", clean)
	}
}

// A printed IBAN whose digit groups run on into a following number also
// yields a Luhn-valid card claim. Guarding the merged union of the two would
// reject both and leave the IBAN in the clear.
func TestGuardsJudgeClaimsBeforeMerging(t *testing.T) {
	// BE68 5390 0754 7034 is an IBAN; its last three groups and the 1008
	// after it are a Luhn-valid 4-4-4-4 card.
	clean, _ := New().Redact(context.Background(), "Wire BE68 5390 0754 7034 1008 EUR")
	if want := "Wire [IBAN] EUR"; clean != want {
		t.Errorf("got  %q\nwant %q", clean, want)
	}
}

func TestNewWithPresidioKeepsRegexFloorFirst(t *testing.T) {
	c := NewWithPresidio("http://127.0.0.1:1") // deliberately dead
	clean, errs := c.Redact(context.Background(), "SSN 078-05-1120 on file.")
	if errs == nil {
		t.Fatal("expected an error from the dead sidecar")
	}
	if !strings.Contains(clean, "[SSN]") {
		t.Errorf("floor should still redact when the sidecar is down: %q", clean)
	}
}

// The quickstart builds a chain per call. That used to recompile every
// built-in regex each time: 3x the latency and 50x the memory of reuse.
func TestNewDoesNotRecompileBuiltins(t *testing.T) {
	if n := testing.AllocsPerRun(10, func() { New() }); n > 10 {
		t.Errorf("New made %.0f allocations, want the compiled builtins shared", n)
	}
}

// A Chain literal with no detectors used to hand the text back in the clear
// with no error. It now redacts with the floor and says why.
func TestEmptyChainFailsClosed(t *testing.T) {
	clean, errs := (&Chain{}).Redact(context.Background(), "ssn 078-05-1120")
	if !errors.Is(errs, ErrNoDetectors) {
		t.Errorf("errs = %v, want [ErrNoDetectors]", errs)
	}
	if want := "ssn [SSN]"; clean != want {
		t.Errorf("got %q, want %q", clean, want)
	}
}

// Zero values of the engines must not panic: a zero Regex reads with the
// built-ins, a zero Presidio reports an error.
func TestZeroValueDetectors(t *testing.T) {
	var r Regex
	spans, err := r.Detect(context.Background(), "ssn 078-05-1120")
	if err != nil || len(spans) != 1 || spans[0].Type != "SSN" {
		t.Errorf("zero Regex: spans %v, err %v; want one SSN", spans, err)
	}
	if _, err := (&Presidio{}).Detect(context.Background(), "x"); err == nil {
		t.Error("zero Presidio: want an error for its missing URL")
	}
}

// The floor used to ignore ctx: 4 MB with a cancelled ctx ran ~2.5 s and
// returned no error. It must stop and report the cancellation.
func TestRegexFloorHonoursCancellation(t *testing.T) {
	text := strings.Repeat("ssn 078-05-1120, mail jane.doe%40example.org; ", 4<<20/47)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, errs := New().Run(ctx, text)
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Errorf("cancelled run took %v, want it to stop early", d)
	}
	if !errors.Is(errs, context.Canceled) {
		t.Errorf("errs = %v, want the cancellation reported", errs)
	}
}

// The chain's per-detector Timeout is for a sidecar; the in-process floor must
// not come back partly read because of it, or a large text leaks its tail.
func TestChainTimeoutDoesNotCutTheFloor(t *testing.T) {
	text := strings.Repeat("nothing to see here. ", 2000) + "ssn 219-09-9999"
	c := &Chain{Detectors: []Detector{NewRegex()}, Timeout: time.Nanosecond}
	got, errs := c.Redact(context.Background(), text)
	if errs != nil || !strings.HasSuffix(got, "ssn [SSN]") {
		t.Fatalf("Redact with a 1ns Timeout: errs %v, tail %q", errs, got[len(got)-20:])
	}
}
