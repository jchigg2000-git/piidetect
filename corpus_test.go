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
//     and per-shape tables (go test -v -run Corpus) are the report, not the
//     gate.
//   - Optional fields. An entry may carry "shape" (log, json, csv, form,
//     clinical, code, prose, markup or pasted: the kind of text it stands
//     for) and "targets" (the types its traps are aimed at). Neither affects
//     scoring; the loader ignores fields it does not know and accepts entries
//     without them. Entries without a shape are reported as "untagged".
//
// Per-entry results. Set PIIDETECT_CORPUS_RESULTS to a file path and
// TestRegexCorpusFloors writes one JSON document there, so a port scored by
// the same rules can diff entry by entry rather than by totals:
//
//	PIIDETECT_CORPUS_RESULTS=/tmp/go.json go test -run TestRegexCorpusFloors .
//
// The document is {"engine":"regex","entries":[...]}, one per entry the
// regex floor scores, in corpus order. Each has "name", and "shape" and
// "targets" as authored; "values", each marked value with "type", "value",
// "start", "end" and "found"; "traps", each trap with "value", "start",
// "end", "fired" and, when fired, "by" (the types of the spans that hit it);
// and "unmarked", every false-positive claim with "type", "value", "start"
// and "end". Offsets are bytes into the marker-stripped text; a port counting
// UTF-16 units should match on "value" and order instead. Exempt types
// (PERSON_NAME, ADDRESS) are left out of "values". The file is written even
// when the test fails, which is when it is most useful.
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
	Shape   string   `json:"shape,omitempty"`
	Targets []string `json:"targets,omitempty"`

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

// entryResult is one entry's outcome, as written by PIIDETECT_CORPUS_RESULTS.
type entryResult struct {
	Name     string        `json:"name"`
	Shape    string        `json:"shape,omitempty"`
	Targets  []string      `json:"targets,omitempty"`
	Values   []valueResult `json:"values"`
	Traps    []trapResult  `json:"traps"`
	Unmarked []claimResult `json:"unmarked"`
}

type valueResult struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Start int    `json:"start"`
	End   int    `json:"end"`
	Found bool   `json:"found"`
}

type trapResult struct {
	Value string   `json:"value"`
	Start int      `json:"start"`
	End   int      `json:"end"`
	Fired bool     `json:"fired"`
	By    []string `json:"by,omitempty"`
}

type claimResult struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

// scoreRegexEntry applies the scoring rules above to one entry's spans,
// adding to score and failing t once per miss, fired trap or false positive.
// It returns the entry's result for the per-shape table and the results file.
func scoreRegexEntry(t *testing.T, e corpusEntry, spans []Span, score map[string]*typeScore) entryResult {
	t.Helper()
	res := entryResult{Name: e.Name, Shape: e.Shape, Targets: e.Targets,
		Values: []valueResult{}, Traps: []trapResult{}, Unmarked: []claimResult{}}
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
		val := e.Text[truth.Start:truth.End]
		res.Values = append(res.Values, valueResult{truth.Type, val, truth.Start, truth.End, matched})
		if matched {
			row(truth.Type).found++
		} else {
			// A miss fails on its own: against a corpus this size a recall
			// floor tolerates one silent miss, which is how "MRN: 86753090"
			// once went undetected while the test passed.
			row(truth.Type).missed++
			t.Errorf("%s: missed %s %q", e.Name, truth.Type, val)
		}
	}
	for _, trap := range e.Traps {
		res.Traps = append(res.Traps, trapResult{Value: e.Text[trap.Start:trap.End], Start: trap.Start, End: trap.End})
	}
	for _, sp := range spans {
		trapped := false
		for i, trap := range e.Traps {
			if overlaps(sp, trap) {
				trapped = true
				res.Traps[i].Fired = true
				res.Traps[i].By = append(res.Traps[i].By, sp.Type)
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
			res.Unmarked = append(res.Unmarked, claimResult{sp.Type, e.Text[sp.Start:sp.End], sp.Start, sp.End})
			t.Errorf("%s: false positive %s %q", e.Name, sp.Type, e.Text[sp.Start:sp.End])
		}
	}
	return res
}

// logShapeTable prints one line per shape (entries without one are
// "untagged"): entries, values found and missed, false positives, and traps
// fired out of traps set.
func logShapeTable(t *testing.T, results []entryResult) {
	t.Helper()
	type shapeRow struct{ entries, found, missed, fp, fired, traps int }
	rows := map[string]*shapeRow{}
	for _, r := range results {
		shape := r.Shape
		if shape == "" {
			shape = "untagged"
		}
		if rows[shape] == nil {
			rows[shape] = &shapeRow{}
		}
		s := rows[shape]
		s.entries++
		for _, v := range r.Values {
			if v.Found {
				s.found++
			} else {
				s.missed++
			}
		}
		s.fp += len(r.Unmarked)
		for _, tr := range r.Traps {
			s.traps++
			if tr.Fired {
				s.fired++
			}
		}
	}
	shapes := make([]string, 0, len(rows))
	for shape := range rows {
		shapes = append(shapes, shape)
	}
	sort.Strings(shapes)
	var b strings.Builder
	fmt.Fprintf(&b, "regex corpus, per shape:\n%-12s %7s %6s %6s %6s %6s\n", "SHAPE", "entries", "found", "missed", "FP", "traps")
	for _, shape := range shapes {
		s := rows[shape]
		fmt.Fprintf(&b, "%-12s %7d %6d %6d %6d %6s\n", shape, s.entries, s.found, s.missed, s.fp, fmt.Sprintf("%d/%d", s.fired, s.traps))
	}
	b.WriteString("(traps: fired/set)")
	t.Log(b.String())
}

// writeCorpusResults writes the per-entry results to the path in
// PIIDETECT_CORPUS_RESULTS, if it is set (see the header of this file).
func writeCorpusResults(t *testing.T, engine string, results []entryResult) {
	t.Helper()
	path := os.Getenv("PIIDETECT_CORPUS_RESULTS")
	if path == "" {
		return
	}
	out, err := json.MarshalIndent(struct {
		Engine  string        `json:"engine"`
		Entries []entryResult `json:"entries"`
	}{engine, results}, "", "  ")
	if err != nil {
		t.Fatalf("marshal corpus results: %v", err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		t.Fatalf("write corpus results: %v", err)
	}
	t.Logf("wrote %d corpus results to %s", len(results), path)
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

// The optional fields are optional, unknown fields are ignored, and
// PIIDETECT_CORPUS_RESULTS gets each value's and trap's outcome by name.
func TestCorpusResultsFile(t *testing.T) {
	var entries []corpusEntry
	raw := `[{"name":"a","engines":["regex"],"shape":"log","targets":["IP"],"note":"x","marked":"ip «IP|10.1.2.3» ver «TRAP|v2.10.4»"},
		{"name":"b","engines":["regex"],"marked":"none"}]`
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		t.Fatal(err)
	}
	if entries[0].Shape != "log" || entries[1].Shape != "" {
		t.Fatalf("shapes: %+v", entries)
	}
	path := filepath.Join(t.TempDir(), "results.json")
	t.Setenv("PIIDETECT_CORPUS_RESULTS", path)
	var results []entryResult
	for _, e := range entries {
		e.Text, e.Truths, e.Traps = parseMarked(e.Marked)
		spans, _ := NewRegex().Detect(context.Background(), e.Text)
		results = append(results, scoreRegexEntry(t, e, spans, map[string]*typeScore{}))
	}
	writeCorpusResults(t, "regex", results)
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Engine  string        `json:"engine"`
		Entries []entryResult `json:"entries"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Entries) != 2 {
		t.Fatalf("results file: %s", got)
	}
	a := doc.Entries[0]
	if doc.Engine != "regex" || a.Shape != "log" ||
		len(a.Values) != 1 || !a.Values[0].Found || a.Values[0].Value != "10.1.2.3" ||
		len(a.Traps) != 1 || a.Traps[0].Fired || a.Traps[0].Value != "v2.10.4" {
		t.Errorf("results file: %s", got)
	}
}
