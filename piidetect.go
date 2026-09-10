// Package piidetect finds and redacts PII/PHI in text.
//
// It is built as an ordered chain of detectors. The floor is an in-process
// RE2 recognizer set — linear-time, safe on hostile input, no network — whose
// hits are confirmed by typed validators (Luhn, IBAN mod-97, octet range,
// hyphen adjacency) rather than accepted on shape alone. Behind it you can
// optionally put a self-hosted presidio-analyzer sidecar for the free-text
// cases regex cannot reach: names, addresses, narrative PHI.
//
// Spans carry offsets, type and provenance, never the matched value.
package piidetect

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Span is one detected sensitive value: offsets into the scanned text plus
// type and provenance. Never carries the value itself.
type Span struct {
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Type       string  `json:"type"`
	Confidence float64 `json:"confidence"`
	Detector   string  `json:"detector"`
}

// Detector is implemented by every engine.
type Detector interface {
	Name() string
	Detect(ctx context.Context, text string) ([]Span, error)
}

// Chain runs engines in order (fast deterministic floor first), each under
// its own timeout, and merges overlapping spans. Engine errors are collected,
// not fatal — the caller decides what an error means via FAIL_MODE.
type Chain struct {
	Detectors []Detector
	Timeout   time.Duration
	// allow holds map[type]set(lowercased term) from the pattern pack's
	// allow_list rules. Swapped atomically so a hot-reload never tears.
	allow atomic.Value
}

// typeGuards are engine-independent validators applied to every span by
// claimed type: an engine claiming SSN inside ORD-123-45-6789 is overruled
// the same way whichever engine claimed it (Presidio's context boosting has
// no hyphen-adjacency notion; ours does).
var typeGuards = map[string]func(text string, start, end int) bool{
	"SSN":         notHyphenAdjacent,
	"CREDIT_CARD": luhnValid,
	"IP":          validOctets,
	"IBAN":        ibanMod97,
	// spaCy reads "ORD-290" as the airport code → LOCATION → ADDRESS; a real
	// address never sits glued to a hyphenated identifier.
	"ADDRESS": notHyphenAdjacent,
}

// SetPatternPack installs the chain-level half of a pattern pack: the
// allow-list entries. It lives here rather than in one engine because
// suppression must overrule whichever engine made the claim, exactly like
// typeGuards — a term the owner has ruled a false positive must not come back
// because a different detector found it.
func (c *Chain) SetPatternPack(rules []PatternRule) {
	allow := map[string]map[string]struct{}{}
	for _, r := range rules {
		if r.Kind != "allow_list" || len(r.AllowList) == 0 {
			continue
		}
		set, ok := allow[r.Type]
		if !ok {
			set = map[string]struct{}{}
			allow[r.Type] = set
		}
		for _, term := range r.AllowList {
			set[strings.ToLower(term)] = struct{}{}
		}
	}
	c.allow.Store(allow)
}

// allowed reports whether this exact span text has been ruled a false positive
// for this type. Matching is on the span's own text, case-insensitively: an
// allow-list entry suppresses the term, never a region of the document, so it
// cannot be used to smuggle real PII past the filter by neighbouring it.
func (c *Chain) allowed(typ, span string) bool {
	v := c.allow.Load()
	if v == nil {
		return false
	}
	set, ok := v.(map[string]map[string]struct{})[typ]
	if !ok {
		return false
	}
	_, hit := set[strings.ToLower(span)]
	return hit
}

// Run returns merged, guard-validated spans plus one error per failed engine.
func (c *Chain) Run(ctx context.Context, text string) ([]Span, []error) {
	var all []Span
	var errs []error
	for _, d := range c.Detectors {
		dctx, cancel := context.WithTimeout(ctx, c.Timeout)
		spans, err := d.Detect(dctx, text)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d.Name(), err))
			continue
		}
		for _, sp := range spans {
			if guard, ok := typeGuards[sp.Type]; ok && !guard(text, sp.Start, sp.End) {
				continue
			}
			if sp.Start >= 0 && sp.End <= len(text) && c.allowed(sp.Type, text[sp.Start:sp.End]) {
				continue
			}
			all = append(all, sp)
		}
	}
	return Merge(all), errs
}

// Merge sorts spans and collapses overlaps: the union wins the extent, the
// higher confidence wins type and provenance.
func Merge(spans []Span) []Span {
	if len(spans) < 2 {
		return spans
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start != spans[j].Start {
			return spans[i].Start < spans[j].Start
		}
		return spans[i].End > spans[j].End
	})
	out := spans[:1]
	for _, sp := range spans[1:] {
		last := &out[len(out)-1]
		if sp.Start >= last.End {
			out = append(out, sp)
			continue
		}
		if sp.End > last.End {
			last.End = sp.End
		}
		if sp.Confidence > last.Confidence {
			last.Type, last.Detector, last.Confidence = sp.Type, sp.Detector, sp.Confidence
		}
	}
	return out
}
