package piidetect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"sync/atomic"
	"unicode/utf8"
)

// Presidio calls a self-hosted presidio-analyzer sidecar over HTTP — the
// heavy NER tier that catches what regex can't (names, addresses, free-text
// PHI). Self-hosted deliberately: payloads never leave the local boundary.
// Approved pattern-pack rules ride along per call as ad_hoc_recognizers —
// regex rules (with optional context words) and deny-list rules — while
// threshold rules lower the per-type score gate; the flywheel extends and
// retunes Presidio without a container restart.
//
// The entity-type map and default score gate live in vocabulary.go
// (PresidioEntityMap, PresidioDefaultScoreGate). NewPresidio copies the map,
// so edit PresidioEntityMap before constructing: a later edit reaches only
// the instances built after it.
//
// The exported fields are optional settings in the manner of Chain's, each
// with a zero value that means the default. Set them before the first Detect.
type Presidio struct {
	// Language is the analyzer language sent with each request and declared
	// by the pack's ad-hoc recognizers; "" means "en". The sidecar must have
	// an NLP model loaded for it.
	Language string
	// HTTPClient sends the requests; nil means http.DefaultClient. Set one
	// for TLS, a proxy or a transport-level timeout.
	HTTPClient *http.Client
	// MaxChars is the longest text, in characters, sent to the sidecar; zero
	// means DefaultPresidioMaxChars and a negative value means no limit.
	// Longer text is not sent: Detect returns an error, so the caller's
	// fail-closed path applies rather than a sidecar 500.
	MaxChars int

	url      string
	entities map[string]string // PresidioEntityMap as of construction
	pack     atomic.Pointer[compiledPack]
}

// DefaultPresidioMaxChars is Presidio.MaxChars when unset: spaCy's default
// max_length, beyond which the analyzer fails the request.
const DefaultPresidioMaxChars = 1_000_000

// compiledPack is a pattern pack partitioned by kind, precomputed once per
// reload (and per language) instead of per request.
type compiledPack struct {
	rules []PatternRule      // as given, to recompile for another language
	lang  string             // the supported_language adhoc declares
	adhoc []map[string]any   // pattern + deny-list recognizers, payload-ready
	gates map[string]float64 // per-type score gate overrides
	types map[string]bool    // entity types our pack rules declare
}

// NewPresidio returns a Presidio for the sidecar at url
// (e.g. "http://localhost:5002"); a trailing slash is ignored.
func NewPresidio(url string) *Presidio {
	p := &Presidio{url: strings.TrimRight(url, "/"), entities: maps.Clone(PresidioEntityMap)}
	p.pack.Store(&compiledPack{})
	return p
}

func (p *Presidio) Name() string { return "presidio" }

func (p *Presidio) language() string {
	if p.Language == "" {
		return "en"
	}
	return p.Language
}

func (p *Presidio) SetPatternPack(rules []PatternRule) {
	p.pack.Store(compilePack(rules, p.language()))
}

func compilePack(rules []PatternRule, lang string) *compiledPack {
	c := &compiledPack{rules: rules, lang: lang, gates: map[string]float64{}, types: map[string]bool{}}
	for _, r := range rules {
		c.types[r.Type] = true
		switch {
		case r.isRegex():
			rec := map[string]any{
				"name":               "pack-" + r.ID,
				"supported_language": lang,
				"supported_entity":   r.Type,
				"patterns": []map[string]any{
					{"name": r.ID, "regex": r.Regex, "score": r.confidence()},
				},
			}
			if len(r.Context) > 0 {
				rec["context"] = r.Context
			}
			c.adhoc = append(c.adhoc, rec)
		case r.Kind == "deny_list" && len(r.DenyList) > 0:
			c.adhoc = append(c.adhoc, map[string]any{
				"name":               "pack-" + r.ID,
				"supported_language": lang,
				"supported_entity":   r.Type,
				"deny_list":          r.DenyList,
			})
		case r.Kind == "threshold" && r.Threshold > 0:
			if g, ok := c.gates[r.Type]; !ok || r.Threshold < g {
				c.gates[r.Type] = r.Threshold
			}
		}
	}
	return c
}

type presidioResult struct {
	EntityType string  `json:"entity_type"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Score      float64 `json:"score"`
}

// Detect asks the sidecar for spans. A zero Presidio carries no pack and uses
// http.DefaultClient; with no URL its requests fail and say so. Text longer
// than MaxChars is not sent, and a non-200 reply is reported with the start of
// its body.
func (p *Presidio) Detect(ctx context.Context, text string) ([]Span, error) {
	limit := p.MaxChars
	if limit == 0 {
		limit = DefaultPresidioMaxChars
	}
	if limit > 0 && len(text) > limit {
		if n := utf8.RuneCountInString(text); n > limit {
			return nil, fmt.Errorf("presidio: text is %d characters, over MaxChars %d; not sent", n, limit)
		}
	}
	lang := p.language()
	pack := p.pack.Load()
	if pack == nil {
		pack = &compiledPack{}
	}
	if pack.lang != lang && len(pack.rules) > 0 {
		// Language was set after SetPatternPack: the recognizers must declare
		// the request's language or the analyzer skips them. Keep the result
		// unless a reload got in first.
		next := compilePack(pack.rules, lang)
		p.pack.CompareAndSwap(pack, next)
		pack = next
	}
	client := p.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	entities := p.entities
	if entities == nil {
		entities = PresidioEntityMap // zero Presidio: no URL, so its request fails first
	}

	// The request-level threshold must sit at the lowest gate so a lowered
	// per-type gate actually receives candidates; everything else is
	// re-filtered per type below.
	reqThreshold := PresidioDefaultScoreGate
	for _, g := range pack.gates {
		if g < reqThreshold {
			reqThreshold = g
		}
	}
	payload := map[string]any{
		"text":            text,
		"language":        lang,
		"score_threshold": reqThreshold,
	}
	if len(pack.adhoc) > 0 {
		payload["ad_hoc_recognizers"] = pack.adhoc
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url+"/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Quote the start of the sidecar's own message (a missing language
		// model, spaCy's E088 for overlong text) and drain a bounded rest so
		// the connection can be reused.
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("presidio analyze returned %d: %q", resp.StatusCode, bytes.TrimSpace(msg))
	}
	var results []presidioResult
	// Bound the sidecar read (runs inline per proxied request); normal analyze responses are small.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&results); err != nil {
		return nil, fmt.Errorf("presidio response: %w", err)
	}

	// Presidio offsets are unicode codepoints; Go spans are byte offsets.
	runeToByte := RuneToByteOffsets(text)
	var spans []Span
	for _, r := range results {
		typ, mapped := entities[r.EntityType]
		if !mapped {
			// Only OUR pack's ad-hoc types come back verbatim. An unmapped
			// Presidio built-in (US_ITIN fired first) would bypass the
			// chain-level typeGuards — it must join PresidioEntityMap
			// (vocabulary.go) before it can claim spans.
			if !pack.types[r.EntityType] {
				continue
			}
			typ = r.EntityType
		}
		if typ == "" {
			continue
		}
		if r.Start < 0 || r.End > len(runeToByte)-1 || r.Start >= r.End {
			continue
		}
		gate := PresidioDefaultScoreGate
		if g, ok := pack.gates[typ]; ok {
			gate = g
		}
		if r.Score < gate {
			continue
		}
		spans = append(spans, Span{
			Start: runeToByte[r.Start], End: runeToByte[r.End],
			Type: typ, Confidence: r.Score, Detector: "presidio",
		})
	}
	return spans, nil
}
