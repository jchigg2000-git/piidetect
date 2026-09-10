package piidetect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
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
