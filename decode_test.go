package piidetect

import (
	"context"
	"testing"
)

// Offsets are the contract: a span found in the decoded text must land on the
// escapes of the text as given, no more and no less, or Mask would cut the
// wrong bytes.
func TestDecodedViewMapsOffsets(t *testing.T) {
	text := "a%40b+c%C3%BCd"
	dec, orig, ok := decodedView(text)
	if !ok || dec != "a@b cüd" {
		t.Fatalf("decodedView(%q) = %q, %v", text, dec, ok)
	}
	if len(orig) != len(dec)+1 || orig[len(dec)] != len(text) {
		t.Fatalf("orig = %v, want one entry per decoded byte plus the text length", orig)
	}
	// a  %40  b  +  c  %C3  %BC  d
	for i, want := range []int{0, 1, 4, 5, 6, 7, 10, 13, 14} {
		if orig[i] != want {
			t.Errorf("orig[%d] = %d, want %d (orig %v)", i, orig[i], want, orig)
		}
	}
}

// Ordinary text must not pay for a second pass: no escape and no form-encoded
// space means no view and no allocation, and a malformed escape is not one.
func TestDecodedViewOnlyForEncodedText(t *testing.T) {
	for _, plain := range []string{
		"", "Order 12 shipped", "100%", "50%4", "%zz and %4", "C++ and +1 415 555 0173", "1 +", "+x",
	} {
		if _, _, ok := decodedView(plain); ok {
			t.Errorf("decodedView(%q) = ok, want no view", plain)
		}
	}
	if n := testing.AllocsPerRun(10, func() { decodedView("Order 12 shipped, 100%") }); n != 0 {
		t.Errorf("plain text allocated %.0f times in decodedView", n)
	}
	for _, enc := range []string{"a%40b", "a+b", "x=%2B1"} {
		if _, _, ok := decodedView(enc); !ok {
			t.Errorf("decodedView(%q) = no view, want one", enc)
		}
	}
}

// The values of a query string or form body, masked whole and exactly, through
// the chain: its type guards read the text as given, so a span found in the
// decoded text must not be judged there a second time.
func TestRedactPercentEncodedValues(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"mailto:jane.doe%40example.org?subject=hi", "mailto:[EMAIL]?subject=hi"},
		{"card=4111+1111+1111+1111&x=1", "card=[CREDIT_CARD]&x=1"},
		{"card=4111%201111%201111%201111&x=1", "card=[CREDIT_CARD]&x=1"},
		{"ssn=219%2009%209999&x=1", "ssn=[SSN]&x=1"},
		{"q=DOB%3A%203%2F14%2F1985+ok", "q=DOB%3A%20[DOB]+ok"},
		{"q=Patient+MRN%3A%204481920+seen", "q=Patient+[MRN]+seen"},
		{"tel=%2B14155550173", "tel=[PHONE]"},
		{"ip=192%2E168%2E1%2E100", "ip=[IP]"},
		{"iban=DE89%203704%200044%200532%200130%2000", "iban=[IBAN]"},
		// Decoded, it is still a hyphenated identifier, and still not an SSN.
		{"ref=ORD%2D123%2D45%2D6789", "ref=ORD%2D123%2D45%2D6789"},
		{"n=1+1&m=a+b&c=C%2B%2B", "n=1+1&m=a+b&c=C%2B%2B"},
	} {
		if got, _ := New().Redact(context.Background(), c.in); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// An allow-list term is ruled on as it reads, so it covers its encoded form.
func TestAllowListMatchesEncodedForm(t *testing.T) {
	text := "mailto:support%40example.com and mailto:jane%40example.com"
	c := New()
	c.SetPatternPack([]PatternRule{{ID: "ours", Type: "EMAIL", Kind: "allow_list", AllowList: []string{"support@example.com"}}})
	if got, _ := c.Redact(context.Background(), text); got != "mailto:support%40example.com and mailto:[EMAIL]" {
		t.Errorf("got %q", got)
	}
}
