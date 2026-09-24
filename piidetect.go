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
// not fatal — the caller decides what an error means (fail open or closed)
// from the returned errors.
type Chain struct {
	Detectors []Detector
	// Timeout bounds each detector on a Run; zero means DefaultTimeout.
	Timeout time.Duration
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
	"IP":          validIP,
	"IBAN":        ibanValid,
	// spaCy reads "ORD-290" as the airport code → LOCATION → ADDRESS; a real
	// address never sits glued to a hyphenated identifier.
	"ADDRESS": notHyphenAdjacent,
}

// rawDetector is implemented by engines whose Detect merges their own hits.
// The chain takes the unmerged hits instead, so each type guard judges one
// claim on its own extent — never its union with a neighbouring claim of
// another type, which no guard would accept — and merges once, after guarding.
type rawDetector interface {
	detectRaw(ctx context.Context, text string) ([]Span, error)
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
//
// A span with offsets outside text is dropped and reported as its engine's
// error. Kept, it would panic in a type guard, or merge with valid neighbours
// into a union Mask cannot apply — leaving all of them in the clear.
func (c *Chain) Run(ctx context.Context, text string) ([]Span, []error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	var all []Span
	var errs []error
	for _, d := range c.Detectors {
		dctx, cancel := context.WithTimeout(ctx, timeout)
		var spans []Span
		var err error
		if rd, ok := d.(rawDetector); ok {
			spans, err = rd.detectRaw(dctx, text)
		} else {
			spans, err = d.Detect(dctx, text)
		}
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d.Name(), err))
			continue
		}
		bad := 0
		for _, sp := range spans {
			if sp.Start == sp.End {
				continue // claims nothing
			}
			if !sp.within(text) {
				bad++
				continue
			}
			if guard, ok := typeGuards[sp.Type]; ok && !guard(text, sp.Start, sp.End) {
				continue
			}
			if c.allowed(sp.Type, text[sp.Start:sp.End]) {
				continue
			}
			all = append(all, sp)
		}
		if bad > 0 {
			errs = append(errs, fmt.Errorf("%s: dropped %d span(s) with offsets outside the text", d.Name(), bad))
		}
	}
	return Merge(all), errs
}

// within reports whether sp is a non-empty span inside text.
func (sp Span) within(text string) bool {
	return 0 <= sp.Start && sp.Start < sp.End && sp.End <= len(text)
}

// Merge sorts spans and collapses overlaps: the union wins the extent, the
// higher confidence wins type and provenance. It sorts and overwrites spans in
// place and returns a prefix of it.
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
