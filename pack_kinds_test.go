package piidetect

// Pattern-pack kinds (G6-full slice): regex rules become pattern recognizers
// (with context words), deny-list rules become deny-list recognizers,
// threshold rules become per-type score gates — and the regex engine ignores
// everything that isn't a regex.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func kindsPack() []PatternRule {
	return []PatternRule{
		{ID: "r1", Type: "MRN", Kind: "regex", Regex: `\bMRN\d+\b`, Confidence: 0.7, Context: []string{"mrn", "medical record"}},
		{ID: "d1", Type: "PERSON_NAME", Kind: "deny_list", DenyList: []string{"Diego Mensah", "Kofi Novak"}},
		{ID: "t1", Type: "PERSON_NAME", Kind: "threshold", Threshold: 0.25},
	}
}

func TestPresidioPackKindsPayloadAndGates(t *testing.T) {
	var gotPayload map[string]any
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotPayload)
		// PERSON at 0.30: above the lowered PERSON_NAME gate (0.25), kept.
		// PHONE_NUMBER at 0.30: under the default 0.40 gate, dropped.
		_, _ = io.WriteString(w, `[
			{"entity_type":"PERSON","start":5,"end":9,"score":0.30},
			{"entity_type":"PHONE_NUMBER","start":13,"end":23,"score":0.30}
		]`)
	}))
	defer stub.Close()

	p := NewPresidio(stub.URL)
	p.SetPatternPack(kindsPack())

	spans, err := p.Detect(context.Background(), "call Jane at 5551234567")
	if err != nil {
		t.Fatal(err)
	}

	// Request threshold must sit at the lowest gate so lowered types receive
	// candidates at all.
	if th, _ := gotPayload["score_threshold"].(float64); th != 0.25 {
		t.Errorf("score_threshold = %v, want 0.25", gotPayload["score_threshold"])
	}
	adhoc, _ := gotPayload["ad_hoc_recognizers"].([]any)
	if len(adhoc) != 2 {
		t.Fatalf("ad_hoc_recognizers = %v, want regex + deny_list (threshold is a gate, not a recognizer)", adhoc)
	}
	byName := map[string]map[string]any{}
	for _, a := range adhoc {
		rec := a.(map[string]any)
		byName[rec["name"].(string)] = rec
	}
	if rec := byName["pack-r1"]; rec == nil || rec["context"] == nil {
		t.Errorf("regex recognizer missing context words: %v", rec)
	}
	if rec := byName["pack-d1"]; rec == nil {
		t.Error("deny-list recognizer missing")
	} else if dl, _ := rec["deny_list"].([]any); len(dl) != 2 {
		t.Errorf("deny_list = %v", rec["deny_list"])
	}

	if len(spans) != 1 || spans[0].Type != "PERSON_NAME" {
		t.Fatalf("spans = %+v, want only PERSON_NAME (PHONE under its default gate)", spans)
	}
}

// The two trap FPs caught live on 2026-07-02: US_ITIN claiming the tail of
// an ORD- order number (unmapped type bypassing the guards), and LOCATION
// reading "ORD-970" as an airport code. Unmapped built-ins must be dropped;
// mapped types must pass the chain guards.
func TestPresidioTrapShapesStaySilent(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[
			{"entity_type":"US_ITIN","start":19,"end":30,"score":0.5},
			{"entity_type":"LOCATION","start":15,"end":22,"score":0.85},
			{"entity_type":"US_DRIVER_LICENSE","start":0,"end":5,"score":0.9}
		]`)
	}))
	defer stub.Close()

	p := NewPresidio(stub.URL)
	chain := &Chain{Detectors: []Detector{p}, Timeout: time.Second}
	spans, errs := chain.Run(context.Background(), "Where is order ORD-970-91-7304?")
	if len(errs) > 0 {
		t.Fatalf("chain errors: %v", errs)
	}
	if len(spans) != 0 {
		t.Errorf("trap shapes produced spans: %+v (ITIN→SSN and LOCATION→ADDRESS must fail the hyphen guard; unmapped types must drop)", spans)
	}
}

func TestRegexIgnoresPresidioConfigKinds(t *testing.T) {
	r := NewRegex()
	if err := r.SetPatternPack(kindsPack()); err != nil {
		t.Fatalf("non-regex kinds must not fail regex compilation: %v", err)
	}
	spans, _ := r.Detect(context.Background(), "note for Diego Mensah re MRN12345")
	for _, sp := range spans {
		if sp.Type == "PERSON_NAME" {
			t.Errorf("regex engine applied a deny-list rule: %+v", sp)
		}
	}
	found := false
	for _, sp := range spans {
		if sp.Type == "MRN" {
			found = true
		}
	}
	if !found {
		t.Error("regex-kind pack rule should still compile and match")
	}
}
