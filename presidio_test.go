package piidetect

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPresidioPayloadMappingAndOffsets(t *testing.T) {
	var gotPayload map[string]any
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotPayload)
		// "héllo John Smith" — Presidio speaks rune offsets: John=6..10 in
		// runes but 7..11 in bytes (é is 2 bytes). Also one DATE_TIME to drop
		// and one unmapped ad-hoc type to pass through verbatim.
		_, _ = io.WriteString(w, `[
			{"entity_type":"PERSON","start":6,"end":16,"score":0.85},
			{"entity_type":"DATE_TIME","start":0,"end":5,"score":0.9},
			{"entity_type":"MRN","start":0,"end":5,"score":0.7}
		]`)
	}))
	defer stub.Close()

	p := NewPresidio(stub.URL)
	p.SetPatternPack([]PatternRule{{ID: "r1", Type: "MRN", Regex: `\bMRN\d+\b`, Confidence: 0.7}})

	spans, err := p.Detect(context.Background(), "héllo John Smith")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if gotPayload["language"] != "en" || gotPayload["text"] != "héllo John Smith" {
		t.Errorf("payload = %v", gotPayload)
	}
	adhoc, _ := gotPayload["ad_hoc_recognizers"].([]any)
	if len(adhoc) != 1 {
		t.Errorf("ad_hoc_recognizers missing: %v", gotPayload["ad_hoc_recognizers"])
	}

	if len(spans) != 2 {
		t.Fatalf("spans = %+v, want PERSON_NAME + ad-hoc MRN (DATE_TIME dropped)", spans)
	}
	var person *Span
	for i := range spans {
		if spans[i].Type == "PERSON_NAME" {
			person = &spans[i]
		}
	}
	if person == nil {
		t.Fatalf("no PERSON_NAME span: %+v", spans)
	}
	if person.Start != 7 || person.End != 17 {
		t.Errorf("byte offsets = [%d,%d), want [7,17) after rune conversion", person.Start, person.End)
	}
	if person.Detector != "presidio" {
		t.Errorf("detector = %q", person.Detector)
	}
}

func TestPresidioErrorSurfaces(t *testing.T) {
	p := NewPresidio("http://127.0.0.1:1") // nothing listens
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := p.Detect(ctx, "text"); err == nil {
		t.Error("want connection error surfaced (the caller decides what it means)")
	}
}

// Live integration against the real sidecar; skips unless it's up.
// Run: docker run -d -p 8126:3000 mcr.microsoft.com/presidio-analyzer
func TestPresidioLiveNamesAndAddresses(t *testing.T) {
	url := "http://127.0.0.1:8126"
	probe, err := http.Get(url + "/health")
	if err != nil {
		t.Skipf("presidio sidecar not running: %v", err)
	}
	probe.Body.Close()

	p := NewPresidio(url)
	det := NewRegex()
	chain := &Chain{Detectors: []Detector{det, p}, Timeout: 3 * time.Second}

	for _, e := range loadCorpus(t) {
		if !hasEngine(e, "presidio") {
			continue
		}
		spans, errs := chain.Run(context.Background(), e.Text)
		if len(errs) > 0 {
			t.Fatalf("%s: chain errors: %v", e.Name, errs)
		}
		for _, truth := range e.Truths {
			if truth.Type != "PERSON_NAME" && truth.Type != "ADDRESS" {
				continue
			}
			found := false
			for _, sp := range spans {
				if overlaps(sp, truth) && sp.Type == truth.Type {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: presidio missed %s %q (got %+v)", e.Name, truth.Type, e.Text[truth.Start:truth.End], spans)
			}
		}
	}
}

// A trailing-slash URL used to POST to //analyze; a 500 came back as a bare
// status with its body unread; text past spaCy's max_length was sent anyway.
func TestPresidioClientEdges(t *testing.T) {
	var hits atomic.Int32
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/analyze" {
			http.NotFound(w, r)
			return
		}
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["language"] != "de" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error": "No matching recognizers were found to serve the request."}`+strings.Repeat(" pad", 300))
			return
		}
		_, _ = io.WriteString(w, `[]`)
	}))
	defer stub.Close()

	p := NewPresidio(stub.URL + "/")
	p.HTTPClient = stub.Client()
	if _, err := p.Detect(context.Background(), "text"); err == nil ||
		!strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "No matching recognizers") {
		t.Errorf("500 error = %v; want the status and the sidecar's message", err)
	} else if len(err.Error()) > 600 {
		t.Errorf("500 error quotes %d bytes; want at most ~512 of the body", len(err.Error()))
	}

	p.Language = "de"
	if _, err := p.Detect(context.Background(), "text"); err != nil {
		t.Errorf("trailing-slash URL with Language de: %v", err)
	}

	p.MaxChars = 5
	before := hits.Load()
	if _, err := p.Detect(context.Background(), "héllo!"); err == nil {
		t.Error("6 characters over MaxChars 5: want an error")
	}
	if _, err := p.Detect(context.Background(), "héllo"); err != nil {
		t.Errorf("5 characters (6 bytes) at MaxChars 5: %v", err)
	}
	if got := hits.Load() - before; got != 1 {
		t.Errorf("sidecar saw %d requests; want 1 (the overlong text is not sent)", got)
	}
}
