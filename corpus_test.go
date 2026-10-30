// Corpus scoring rules. The golden corpus in testdata/corpus/*.json is the
// shared truth for this library and its TypeScript port; a port that scores
// the same entries by these rules gets comparable numbers.
//
//   - Markup. An entry's "marked" text carries «TYPE|value» markers. Stripping
//     them gives the text a detector sees; each marker's value becomes a truth
//     span (a trap span when TYPE is TRAP) at its byte offsets in that text.
//   - Engines. An entry is scored only by the engines it lists. The regex
//     scorers (TestRegexCorpusFloors, TestCorpusRedactEndToEnd) skip entries
//     without "regex"; the live Presidio test runs only entries listing
//     "presidio".
//   - Exempt types. PERSON_NAME and ADDRESS have no regex recognizer, so the
//     regex scorers ignore those truths. Only the live Presidio test checks
//     them, and there any same-type overlap counts: a model's name boundaries
//     are not exact.
//   - Found. A truth is found only when one span of the same type covers all
//     of it. A partial hit leaves part of the value in the redacted text, so
//     it counts as missed.
//   - Traps fire on any overlap. A span of any type that overlaps a trap span
//     by even one byte fires it. That span is counted under its own type as a
//     trap, not also as a false positive.
//   - False positives. Any other span that does not overlap a truth of its
//     own type is a false positive, including a span of a different type on a
//     marked value (an SSN span on a phone number is wrong even though the
//     digits get masked).
//   - Zero tolerance. Every miss, fired trap and false positive fails the test
//     on its own; there is no ratio floor to hide one behind. The per-type
//     table (go test -v -run Corpus) is the report, not the gate.
package piidetect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The golden corpus is authored with «TYPE|value» markers; the loader derives
// clean text plus exact truth offsets, so spans never have to be hand-counted.
// TRAP spans mark values that must NOT be detected.
type corpusEntry struct {
	Name    string   `json:"name"`
	Engines []string `json:"engines"`
	Marked  string   `json:"marked"`

	Text   string `json:"-"`
	Truths []Span `json:"-"`
	Traps  []Span `json:"-"`
}

var markerRE = regexp.MustCompile(`«([A-Z_]+)\|([^»]*)»`)

func parseMarked(marked string) (string, []Span, []Span) {
	var text string
	var truths, traps []Span
	last := 0
	for _, m := range markerRE.FindAllStringSubmatchIndex(marked, -1) {
		text += marked[last:m[0]]
		typ := marked[m[2]:m[3]]
		val := marked[m[4]:m[5]]
		sp := Span{Start: len(text), End: len(text) + len(val), Type: typ}
		if typ == "TRAP" {
			traps = append(traps, sp)
		} else {
			truths = append(truths, sp)
		}
		text += val
		last = m[1]
	}
	text += marked[last:]
	return text, truths, traps
}

func loadCorpus(t *testing.T) []corpusEntry {
	t.Helper()
	var all []corpusEntry
	files, err := filepath.Glob(filepath.Join("testdata", "corpus", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus files: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var entries []corpusEntry
		if err := json.Unmarshal(raw, &entries); err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for i := range entries {
			entries[i].Text, entries[i].Truths, entries[i].Traps = parseMarked(entries[i].Marked)
		}
		all = append(all, entries...)
	}
	return all
}

func hasEngine(e corpusEntry, engine string) bool {
	for _, x := range e.Engines {
		if x == engine {
			return true
		}
	}
	return false
}

func overlaps(a, b Span) bool { return a.Start < b.End && b.Start < a.End }

func covers(outer, inner Span) bool { return outer.Start <= inner.Start && outer.End >= inner.End }

// regexExempt reports truth types the regex floor is not scored on.
func regexExempt(typ string) bool { return typ == "PERSON_NAME" || typ == "ADDRESS" }

// typeScore is one row of the per-type table.
type typeScore struct{ found, missed, fp, traps int }

// scoreRegexEntry applies the scoring rules above to one entry's spans,
// adding to score and failing t once per miss, fired trap or false positive.
func scoreRegexEntry(t *testing.T, e corpusEntry, spans []Span, score map[string]*typeScore) {
	t.Helper()
	row := func(typ string) *typeScore {
		if score[typ] == nil {
			score[typ] = &typeScore{}
		}
		return score[typ]
	}
	for _, truth := range e.Truths {
		if regexExempt(truth.Type) {
			continue
		}
		matched := false
		for _, sp := range spans {
			if sp.Type == truth.Type && covers(sp, truth) {
				matched = true
				break
			}
		}
		if matched {
			row(truth.Type).found++
		} else {
			// A miss fails on its own: against a corpus this size a recall
			// floor tolerates one silent miss, which is how "MRN: 86753090"
			// once went undetected while the test passed.
			row(truth.Type).missed++
			t.Errorf("%s: missed %s %q", e.Name, truth.Type, e.Text[truth.Start:truth.End])
		}
	}
	for _, sp := range spans {
		trapped := false
		for _, trap := range e.Traps {
			if overlaps(sp, trap) {
				trapped = true
				t.Errorf("%s: trap fired — %s detected inside a %q trap span", e.Name, sp.Type, e.Text[trap.Start:trap.End])
			}
		}
		if trapped {
			row(sp.Type).traps++
			continue
		}
		hit := false
		for _, truth := range e.Truths {
			if truth.Type == sp.Type && overlaps(sp, truth) {
				hit = true
				break
			}
		}
		if !hit {
			row(sp.Type).fp++
			t.Errorf("%s: false positive %s %q", e.Name, sp.Type, e.Text[sp.Start:sp.End])
		}
	}
}

// logScoreTable prints the per-type table, visible with go test -v.
func logScoreTable(t *testing.T, title string, score map[string]*typeScore) {
	t.Helper()
	types := make([]string, 0, len(score))
	for typ := range score {
		types = append(types, typ)
	}
	sort.Strings(types)
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%-12s %6s %6s %6s %6s\n", title, "TYPE", "found", "missed", "FP", "traps")
	var total typeScore
	for _, typ := range types {
		r := score[typ]
		fmt.Fprintf(&b, "%-12s %6d %6d %6d %6d\n", typ, r.found, r.missed, r.fp, r.traps)
		total.found += r.found
		total.missed += r.missed
		total.fp += r.fp
		total.traps += r.traps
	}
	fmt.Fprintf(&b, "%-12s %6d %6d %6d %6d", "TOTAL", total.found, total.missed, total.fp, total.traps)
	t.Log(b.String())
}

// Every marked value the regex floor is scored on must be gone from the
// output of the one-call path, not just reported by Detect: this catches a
// Chain or Mask change that drops or misplaces spans the detector found.
func TestCorpusRedactEndToEnd(t *testing.T) {
	chain := New()
	checked := 0
	for _, e := range loadCorpus(t) {
		if !hasEngine(e, "regex") {
			continue
		}
		out, errs := chain.Redact(context.Background(), e.Text)
		if len(errs) > 0 {
			t.Fatalf("%s: %v", e.Name, errs)
		}
		for _, truth := range e.Truths {
			if regexExempt(truth.Type) {
				continue
			}
			checked++
			if val := e.Text[truth.Start:truth.End]; strings.Contains(out, val) {
				t.Errorf("%s: %s %q survives Redact: %q", e.Name, truth.Type, val, out)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no regex corpus values checked")
	}
}
