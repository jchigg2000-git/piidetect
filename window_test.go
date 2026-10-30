package piidetect

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// The normalized view is read in windows around the bytes normalizing changed
// (window.go). Read whole instead, it must give the same result: the same
// merged spans from Detect, and the same spans once the chain has judged them.
// Checked on every corpus entry, as given and with an escape or look-alike
// put at each value's edges and middle, and on the benchmark inputs with them
// put at several places, among them right against each value.
func TestWindowedViewMatchesFullRead(t *testing.T) {
	ctx := context.Background()
	packed := NewRegex()
	if err := packed.SetPatternPack([]PatternRule{
		{ID: "acct", Type: "ACCOUNT", Regex: `(?i)\bacct[ #:]*\d{6,}\b`},
		{ID: "dotted-ssn", Type: "SSN", Regex: `\b\d{3}\.\d{2}\.\d{4}\b`},
		// Admits every byte, so it has no cut byte and reads the whole view.
		{ID: "token", Type: "TOKEN", Regex: `tok_[\s\S]{8}`},
	}); err != nil {
		t.Fatal(err)
	}
	detectors := []*Regex{NewRegex(), packed}
	// One of each decode and fold: percent, a Unicode space, JSON, HTML, a
	// dropped invisible, twice-percent, a form space and a dash.
	escapes := []string{"%20", "\u00a0", `\n`, "&#64;", "\u200b", "%2540", "+", "–"}
	sweep := 4 << 10 // see the benchmark inputs below
	if raceEnabled {
		escapes, sweep = escapes[:3], 1<<10
	}

	compared := 0
	same := func(name, text string, dets []*Regex) {
		t.Helper()
		for _, r := range dets {
			full, err := r.detect(ctx, text, false)
			if err != nil {
				t.Fatal(err)
			}
			win, err := r.detect(ctx, text, true)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := chainJudged(text, win), chainJudged(text, full); !slices.Equal(got, want) {
				t.Errorf("%s: chain spans differ on %q:\nwindowed %+v\n   whole %+v", name, clip(text), got, want)
			}
			if got, want := unchecked(Merge(win)), unchecked(Merge(full)); !slices.Equal(got, want) {
				t.Errorf("%s: Detect spans differ on %q:\nwindowed %+v\n   whole %+v", name, clip(text), got, want)
			}
			compared++
		}
	}

	// Spaced digits that %31 shifts by one: every card match after it differs
	// as given and decoded, and one 150 bytes on is valid only decoded.
	digits := "0 1 1 7 6 0 9 7 3 1 4 5 9 5 9 4 0 2 0 0 4 3 5 3 1 0 4 9 0 6 8 2 4 5 4 7 4 3 6 8 2 0 2 1 7 1 5 2 9 2 9 1 1 5 1 3 3 6 9 7 8 8 8 3 4 4 5 4 6 7 6 7 4 8 9 6 3 4 7 7 4 9 1 6 3 8 6 6 7 2 6 1 5 2 9 8 7 0 9 8 9 1 2 8 5 1 3 0 0 1 5 6 9 6 6 5 0 4 7 7 "
	// Texts where a value's verdict or a match's extent turns on a changed
	// byte at the far end of what window.go reads.
	for _, text := range []string{
		// A date range's far end read through a run of blanks: as given the
		// zero-width space ends the far date and makes a range, so the near
		// date is an event; folded away, the far date runs on into the 7.
		"Visited 03/14/1985 - 04/01/2026\u200b7 and left.",
		"Visited 03/14/1985" + strings.Repeat(" ", 120) + "-" + strings.Repeat("\t", 90) + "04/01/2026\u200b7.",
		// An address's ':' path read 300 bytes on, to a %20 that ends it before
		// the "/" that would make it an scp remote.
		"jane.doe@example.org:" + strings.Repeat("a", 300) + "%20/b",
		// A range's near end whose birth label lies some 75 bytes before the far
		// end, encoded.
		"DOBs%3A" + strings.Repeat(" ", 30) + "03/14/1985" + strings.Repeat(" ", 14) + "and" + strings.Repeat(" ", 10) + "04/02/1990",
		// Spaced single digits read as cards back to back.
		"n %31 " + digits + "end",
		"n\u00a0" + digits[2:] + digits + "%2B" + digits + "end",
		// A label glued to an IPv6 address, and an MRN label, across escapes.
		"up inet6:2001:0db8:85a3:0000:0000:8a2e:0370%3A7334 up",
		"Medical&nbsp;Record&nbsp;Number is&#58;&#32;4481920, seen",
	} {
		same("crafted", text, detectors)
	}

	for _, e := range loadCorpus(t) {
		same(e.Name, e.Text, detectors)
		var at []int
		for _, sp := range append(slices.Clone(e.Truths), e.Traps...) {
			mid := sp.Start + (sp.End-sp.Start)/2
			for mid > sp.Start && !runeStart(e.Text, mid) {
				mid--
			}
			at = append(at, sp.Start, mid, sp.End)
		}
		at = append(at, 0, len(e.Text))
		for _, esc := range escapes {
			for _, p := range at {
				same(fmt.Sprintf("%s +%q@%d", e.Name, esc, p), e.Text[:p]+esc+e.Text[p:], detectors[:1])
			}
		}
	}

	for _, s := range benchShapes() {
		// The benchmark's own variants, and the dirty text with an escape
		// around and inside each value at once. The race detector slows a read
		// some twentyfold, so under it they run on the first 16 KB.
		if raceEnabled {
			s.clean = s.clean[:min(len(s.clean), 16<<10)]
		}
		for _, v := range []string{" a%20b ", " a\u00a0b ", ` a\nb `} {
			same(s.name+" bench "+v, benchSplice(s.clean, v), detectors[:1])
		}
		// One escape at a time at fixed places in the clean text, and around
		// and inside each value of the dirty one, on the shape cut to sweep
		// bytes: the windows do not depend on the length of the text around
		// them.
		near := func(dirty string) []int {
			var at []int
			for _, v := range s.dirty {
				v = strings.TrimSpace(v)
				i := strings.Index(dirty, v)
				at = append(at, i-1, i, i+len(v)/2, i+len(v), i+len(v)+1)
			}
			return at
		}
		dirty := benchSplice(s.clean, s.dirty...)
		all := dirty
		for i, at := 0, near(dirty); i < len(at); i++ {
			p := runeFloor(dirty, at[len(at)-1-i])
			all = all[:p] + escapes[i%len(escapes)] + all[p:]
		}
		same(s.name+" dirty, every escape", all, detectors[:1])

		clean := s.clean[:min(len(s.clean), sweep)]
		dirty = benchSplice(clean, s.dirty...)
		var at []int
		for i := 0; i <= 4; i++ {
			at = append(at, len(clean)*i/4)
		}
		for _, esc := range escapes {
			for _, p := range at {
				p = runeFloor(clean, p)
				same(fmt.Sprintf("%s clean +%q@%d", s.name, esc, p), clean[:p]+esc+clean[p:], detectors[:1])
			}
			for _, p := range near(dirty) {
				p = runeFloor(dirty, p)
				same(fmt.Sprintf("%s dirty +%q@%d", s.name, esc, p), dirty[:p]+esc+dirty[p:], detectors[:1])
			}
		}
	}
	t.Logf("%d texts compared", compared)
}

// raceEnabled is set under the race detector; see race_test.go.
var raceEnabled bool

// chainJudged is what Chain.Run makes of one detector's spans, allow list
// aside: a span not checked where it was found is judged by its type guard
// against the text, and the rest are merged.
func chainJudged(text string, spans []Span) []Span {
	var kept []Span
	for _, sp := range spans {
		if guard, ok := typeGuards[sp.Type]; ok && !sp.checked && !guard(text, sp.Start, sp.End) {
			continue
		}
		kept = append(kept, sp)
	}
	return unchecked(Merge(kept))
}

// unchecked clears the flag the chain reads before merging, which a merged
// span takes from whichever of two equal claims sorted first.
func unchecked(spans []Span) []Span {
	out := slices.Clone(spans)
	for i := range out {
		out[i].checked = false
	}
	return out
}

func runeStart(s string, i int) bool { return i >= len(s) || s[i] < 0x80 || s[i] >= 0xC0 }

func runeFloor(s string, i int) int {
	i = max(0, min(i, len(s)))
	for i > 0 && !runeStart(s, i) {
		i--
	}
	return i
}

func clip(s string) string {
	if len(s) > 200 {
		return s[:100] + "…" + s[len(s)-100:]
	}
	return s
}
