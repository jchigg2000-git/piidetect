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

// A +1 number is NANP: ten digits after the +1. Signed counters and offsets
// in logs used to be claimed as E.164 phones; real +1 numbers, encoded or not,
// and other country codes still count.
func TestSignedCountersAreNotPhones(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"delta=+1500000000 bytes", "delta=+1500000000 bytes"},
		{"offset +1048576000 reached", "offset +1048576000 reached"},
		{"ts +1727049600007", "ts +1727049600007"},
		{"area code +11234567890", "area code +11234567890"},
		{"SMS +14155550173 nightly", "SMS [PHONE] nightly"},
		{"tel=%2B14155550173", "tel=[PHONE]"},
		{"UK +442079460958", "UK [PHONE]"},
	} {
		if got, _ := New().Redact(context.Background(), c.in); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A label may be joined to its value by "is" or "was", and the label lists
// cover the camelCase, snake_case and abbreviated keys real records use. The
// title "Mr" and a bare "number" are still not labels.
func TestLabelVerbsAndAliases(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		// One "is"/"was" (or "is:") between label and value.
		{"My SSN is 078051120", "My SSN is [SSN]"},
		{"ssn was: 078051120", "ssn was: [SSN]"},
		{"MRN is 4481920", "[MRN]"},
		{"her date of birth is 1985-03-14", "her date of birth is [DOB]"},
		{"DOB is 3/14/85", "DOB is [DOB]"},
		{"my phone number is 4155550173", "my phone number is [PHONE]"},
		// The added labels.
		{"patientDob: 1985-03-14", "patientDob: [DOB]"},
		{`{"memberDOB":"3/14/85"}`, `{"memberDOB":"[DOB]"}`},
		{"SS#: 078051120", "SS#: [SSN]"},
		{"SS # is 078051120", "SS # is [SSN]"},
		{"Soc Sec #: 078051120", "Soc Sec #: [SSN]"},
		{"ssnNumber=078051120", "ssnNumber=[SSN]"},
		{`{"ssn_number":"078051120"}`, `{"ssn_number":"[SSN]"}`},
		{"Ph: 4155550173", "Ph: [PHONE]"},
		{"cellphone 4155550173", "cellphone [PHONE]"},
		{"mobileNo=4155550173", "mobileNo=[PHONE]"},
		{`{"contactNumber":"4155550173"}`, `{"contactNumber":"[PHONE]"}`},
		{"MR#: 4481920", "[MRN]"},
		// Still not labels.
		{"Your confirmation number is 483920571", "Your confirmation number is 483920571"},
		{"SS 078051120", "SS 078051120"},
		{"Mr 4481920 and MR. 4481920", "Mr 4481920 and MR. 4481920"},
		{"SSN island 078051120", "SSN island 078051120"},
		{"MRN island 4481920", "MRN island 4481920"},
	} {
		if got, _ := New().Redact(context.Background(), c.in); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// After a birth cue a DOB may be a timestamp (masked whole, time and zone
// included) or compact YYYYMMDD; after the MRN label the value may carry a
// letter prefix or internal hyphens. Unlabelled, neither date shape is claimed.
func TestLabelledDOBAndMRNShapes(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`{"dob":"1985-03-14T00:00:00Z"}`, `{"dob":"[DOB]"}`},
		{`{"dob":"1985-03-14T09:30:00.123456789-05:00"}`, `{"dob":"[DOB]"}`},
		{"DOB: 1985-03-14 00:00:00 on file", "DOB: [DOB] on file"},
		{`{"dob":"19850314"}`, `{"dob":"[DOB]"}`},
		{"DOB: 19851314 typo", "DOB: 19851314 typo"},
		{"build 19850314 at 2026-10-22T14:30:00Z", "build 19850314 at 2026-10-22T14:30:00Z"},
		{"MRN: E1234567 seen", "[MRN] seen"},
		{"MRN: AB-1234567 seen", "[MRN] seen"},
		{"MRN: 12-345-678 seen", "[MRN] seen"},
		{"MRN: 4481920-2026", "[MRN]-2026"},
		{"MRN: 12-34 seen", "MRN: 12-34 seen"},
		{"MRN: 12345678901", "MRN: 12345678901"},
		{"MRN: 4481920 12 visits", "[MRN] 12 visits"},
	} {
		if got, _ := New().Redact(context.Background(), c.in); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
