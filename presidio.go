package piidetect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
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
// (PresidioEntityMap, PresidioDefaultScoreGate).
type Presidio struct {
	url  string
	http *http.Client
	pack atomic.Pointer[compiledPack]
}

// compiledPack is a pattern pack partitioned by kind, precomputed once per
// reload instead of per request.
type compiledPack struct {
	adhoc []map[string]any   // pattern + deny-list recognizers, payload-ready
	gates map[string]float64 // per-type score gate overrides
	types map[string]bool    // entity types our pack rules declare
}

func NewPresidio(url string) *Presidio {
	p := &Presidio{url: url, http: &http.Client{}}
	p.pack.Store(&compiledPack{})
	return p
}

func (p *Presidio) Name() string { return "presidio" }

func (p *Presidio) SetPatternPack(rules []PatternRule) {
	c := &compiledPack{gates: map[string]float64{}, types: map[string]bool{}}
	for _, r := range rules {
		c.types[r.Type] = true
		switch {
		case r.isRegex():
			rec := map[string]any{
				"name":               "pack-" + r.ID,
				"supported_language": "en",
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
				"supported_language": "en",
				"supported_entity":   r.Type,
				"deny_list":          r.DenyList,
			})
		case r.Kind == "threshold" && r.Threshold > 0:
			if g, ok := c.gates[r.Type]; !ok || r.Threshold < g {
				c.gates[r.Type] = r.Threshold
			}
		}
	}
	p.pack.Store(c)
}

type presidioResult struct {
	EntityType string  `json:"entity_type"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Score      float64 `json:"score"`
}

func (p *Presidio) Detect(ctx context.Context, text string) ([]Span, error) {
	pack := p.pack.Load()

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
		"language":        "en",
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
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("presidio analyze returned %d", resp.StatusCode)
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
		typ, mapped := PresidioEntityMap[r.EntityType]
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
