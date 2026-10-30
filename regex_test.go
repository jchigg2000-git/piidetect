package piidetect

import (
	"context"
	"testing"
)

// The G2 acceptance gate on regex-detectable corpus entries, scored by the
// rules at the top of corpus_test.go: every value found and fully covered by a
// span of its type, no trap fired, nothing else claimed. Each failure fails on
// its own, so the old 0.95 recall / 0.97 precision floors could never trip and
// are gone. In their place, every type the built-in recognizers emit must be
// exercised by at least one marked value, so dropping or mis-tagging a type's
// entries cannot quietly empty its row. This test is also the CI half of the
// recall ratchet — a pattern change that regresses a type fails here.
func TestRegexCorpusFloors(t *testing.T) {
	det := NewRegex()
	score := map[string]*typeScore{}
	for _, e := range loadCorpus(t) {
		if !hasEngine(e, "regex") {
			continue
		}
		spans, err := det.Detect(context.Background(), e.Text)
		if err != nil {
			t.Fatalf("%s: %v", e.Name, err)
		}
		scoreRegexEntry(t, e, spans, score)
	}
	logScoreTable(t, "regex corpus, per type:", score)
	for _, r := range builtinRecognizers() {
		if s := score[r.typ]; s == nil || s.found+s.missed == 0 {
			t.Errorf("built-in type %s has no marked value in the corpus", r.typ)
		}
	}
}

// Bare 9-digit SSNs are a deliberate v0 miss; a pattern-pack rule closes the
// gap without a restart, and clearing the pack reopens it (the flywheel
// hot-reload contract).
func TestPatternPackHotSwap(t *testing.T) {
	det := NewRegex()
	text := "For verification the SSN on record is 123456789, per the intake call."

	spans, _ := det.Detect(context.Background(), text)
	for _, sp := range spans {
		if sp.Type == "SSN" {
			t.Fatalf("bare SSN unexpectedly caught by builtin: %+v (update this test's premise)", sp)
		}
	}

	err := det.SetPatternPack([]PatternRule{{
		ID: "ssn-bare-context", Type: "SSN",
		Regex:      `(?i)\bSSN(?: on record)?(?: is|:)? ?(\d{9})\b`,
		Confidence: 0.7,
	}})
	if err != nil {
		t.Fatalf("SetPatternPack: %v", err)
	}
	spans, _ = det.Detect(context.Background(), text)
	found := false
	for _, sp := range spans {
		if sp.Type == "SSN" {
			found = true
		}
	}
	if !found {
		t.Error("pattern pack rule did not catch the bare SSN")
	}

	if err := det.SetPatternPack(nil); err != nil {
		t.Fatalf("clear pack: %v", err)
	}
	spans, _ = det.Detect(context.Background(), text)
	for _, sp := range spans {
		if sp.Type == "SSN" {
			t.Error("cleared pack still detecting")
		}
	}
}

func TestPatternPackRejectsBadRegex(t *testing.T) {
	det := NewRegex()
	if err := det.SetPatternPack([]PatternRule{{ID: "bad", Type: "X", Regex: "("}}); err == nil {
		t.Error("want compile error for invalid pattern")
	}
}

// Extent matters as much as detection: the value must be masked whole, and
// must not absorb the text around it. The corpus test checks coverage; this
// checks the exact result.
func TestRedactExactExtent(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		// RE2's \b is ASCII-only: "mü" used to survive in front of the mask.
		{"Schreiben an müller@münchen.de bitte", "Schreiben an [EMAIL] bitte"},
		// No spaces around the address in Japanese; it must not take the words.
		{"連絡先はjane@example.comまで", "連絡先は[EMAIL]まで"},
		{"'jane@example.com' <a@b.co>", "'[EMAIL]' <[EMAIL]>"},
		// The first printed IBAN's greedy match used to swallow the second.
		{"BE68 5390 0754 7034 NL91 ABNA 0417 1643 00", "[IBAN] [IBAN]"},
	} {
		if got, _ := New().Redact(context.Background(), c.in); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
