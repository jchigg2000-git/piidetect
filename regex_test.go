package piidetect

import (
	"context"
	"testing"
)

// The G2 acceptance floors: on regex-detectable corpus entries the built-in
// recognizers hold recall ≥ 0.95 and precision ≥ 0.97, no trap ever fires,
// and — stricter than the floors — no truth is missed or only partly covered
// and nothing unmarked is claimed. This test is also the CI half of the recall
// ratchet — a pattern change that regresses a type fails here.
func TestRegexCorpusFloors(t *testing.T) {
	det := NewRegex()
	var tp, fn, fp int
	for _, e := range loadCorpus(t) {
		if !hasEngine(e, "regex") {
			continue
		}
		spans, err := det.Detect(context.Background(), e.Text)
		if err != nil {
			t.Fatalf("%s: %v", e.Name, err)
		}
		for _, sp := range spans {
			for _, trap := range e.Traps {
				if overlaps(sp, trap) {
					t.Errorf("%s: trap fired — %s detected inside a %q trap span", e.Name, sp.Type, e.Text[trap.Start:trap.End])
				}
			}
		}
		// Presidio-only truths (names, addresses) are not regex's job.
		for _, truth := range e.Truths {
			if truth.Type == "PERSON_NAME" || truth.Type == "ADDRESS" {
				continue
			}
			// A truth counts only when one span of its type covers all of
			// it: a partial hit leaves the rest of the value in the redacted
			// text ("o'" of "o'brien@example.com").
			matched := false
			for _, sp := range spans {
				if covers(sp, truth) && sp.Type == truth.Type {
					matched = true
					break
				}
			}
			if matched {
				tp++
			} else {
				// A miss fails on its own: against a corpus this size the
				// recall floor tolerates one silent miss, which is how
				// "MRN: 86753090" went undetected while this test passed.
				fn++
				t.Errorf("%s: missed %s %q", e.Name, truth.Type, e.Text[truth.Start:truth.End])
			}
		}
		for _, sp := range spans {
			hit := false
			for _, truth := range e.Truths {
				if overlaps(sp, truth) {
					hit = true
					break
				}
			}
			if !hit {
				fp++
				t.Errorf("%s: false positive %s %q", e.Name, sp.Type, e.Text[sp.Start:sp.End])
			}
		}
	}
	recall := float64(tp) / float64(tp+fn)
	precision := float64(tp) / float64(tp+fp)
	if recall < 0.95 {
		t.Errorf("regex recall = %.3f (tp=%d fn=%d), floor 0.95", recall, tp, fn)
	}
	if precision < 0.97 {
		t.Errorf("regex precision = %.3f (tp=%d fp=%d), floor 0.97", precision, tp, fp)
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
