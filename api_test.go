package piidetect

import (
	"context"
	"strings"
	"testing"
)

// The quickstart in the README is this test. If it stops compiling or the
// output changes, the README is wrong and CI says so.
func TestReadmeQuickstart(t *testing.T) {
	clean, errs := New().Redact(context.Background(),
		"Member 078-05-1120 paid with 4111 1111 1111 1111; reach her at jane.doe@example.org.")
	if len(errs) != 0 {
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
	clean, _ := New().Redact(context.Background(), "Wire GB82 WEST 1234 5698 7654 32 190 EUR")
	if want := "Wire [IBAN] EUR"; clean != want {
		t.Errorf("got  %q\nwant %q", clean, want)
	}
}

func TestWithPresidioKeepsRegexFloorFirst(t *testing.T) {
	c := WithPresidio("http://127.0.0.1:1") // deliberately dead
	clean, errs := c.Redact(context.Background(), "SSN 078-05-1120 on file.")
	if len(errs) == 0 {
		t.Fatal("expected an error from the dead sidecar")
	}
	if !strings.Contains(clean, "[SSN]") {
		t.Errorf("floor should still redact when the sidecar is down: %q", clean)
	}
}
