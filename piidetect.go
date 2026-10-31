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
	"errors"
	"fmt"
	"slices"
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

	// checked marks a span its engine has already judged against the text
	// it was found in; see Regex.detectRaw.
	checked bool
}

// Detector is implemented by every engine.
type Detector interface {
	Name() string
	Detect(ctx context.Context, text string) ([]Span, error)
}

// Chain runs engines in order (fast deterministic floor first), each under
// its own timeout, and merges overlapping spans. Engine errors are collected
// into the one error Run returns, not fatal: the spans the other engines
// found, and those a failed engine found before it stopped, are still
// returned. A non-nil error means a value may
// have been missed, so a caller handling regulated data should fail closed on
// one — mask or drop the whole text — rather than send on the partial result.
//
// A Chain with no Detectors runs the built-in regex floor in their place and
// reports ErrNoDetectors, so a zero Chain never returns text unredacted.
type Chain struct {
	Detectors []Detector
	// Timeout bounds each detector on a Run, other than the built-in regex
	// floor, which runs to the end unless ctx itself is done; zero means
	// DefaultTimeout.
	Timeout time.Duration
	// Disable lists types the chain never reports, from any detector: the
	// regex floor skips their recognizers, and a span another detector or a
	// pattern rule claims of one is dropped. Nil means every type, as before.
	// Set it before the first Run; the Type… constants name the built-ins.
	Disable []string
	// allow holds map[type]set(lowercased term) from the pattern pack's
	// allow_list rules. Swapped atomically so a hot-reload never tears.
	allow atomic.Value
	// packErrs holds the []error (each a *DetectorError) detectors returned
	// for the last SetPatternPack; Run reports them until a pack they accept
	// replaces it.
	packErrs atomic.Value
}

// typeGuards are engine-independent validators applied to every span by
// claimed type: an engine claiming SSN inside ORD-123-45-6789 is overruled
// the same way whichever engine claimed it (Presidio's context boosting has
// no hyphen-adjacency notion; ours does).
var typeGuards = map[string]func(text string, start, end int) bool{
	TypeEmail:      emailValid,
	TypeSSN:        ssnValid,
	TypeCreditCard: luhnValid,
	TypeIP:         validIP,
	TypeIBAN:       ibanValid,
	// spaCy reads "ORD-290" as the airport code → LOCATION → ADDRESS; a real
	// address never sits glued to a hyphenated identifier.
	TypeAddress: notHyphenAdjacent,
}

// rawDetector is implemented by engines whose Detect merges their own hits.
// The chain takes the unmerged hits instead, so each type guard judges one
// claim on its own extent — never its union with a neighbouring claim of
// another type, which no guard would accept — and merges once, after guarding.
type rawDetector interface {
	detectRaw(ctx context.Context, text string) ([]Span, error)
}

// SetPatternPack configures the whole chain from one pattern pack. It hands
// the pack to each detector that takes one (Regex, Presidio, or any Detector
// with either SetPatternPack method), replacing the pack that detector held,
// and installs the chain-level half itself: the allow-list entries. A pack of
// allow-list rules only is not forwarded, so a detector configured on its own
// keeps its rules when the chain's allow list changes.
//
// A detector that rejects the pack (the Regex, on a rule RE2 cannot compile;
// the Presidio, on a rule it cannot send) keeps its previous one, and Run
// reports the rejection as that detector's *DetectorError on every call until a pack it accepts is installed — so a bad rule
// fails the caller closed rather than going quietly unapplied.
//
// The allow list lives here rather than in one engine because suppression
// must overrule whichever engine made the claim, exactly like typeGuards — a
// term the owner has ruled a false positive must not come back because a
// different detector found it.
func (c *Chain) SetPatternPack(rules []PatternRule) {
	if slices.ContainsFunc(rules, func(r PatternRule) bool { return r.Kind != "allow_list" }) {
		c.forwardPack(rules)
	}
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

// forwardPack hands rules to each detector that takes a pack, recording the
// rejections Run reports.
func (c *Chain) forwardPack(rules []PatternRule) {
	var errs []error
	for _, d := range c.Detectors {
		switch pd := d.(type) {
		case interface{ SetPatternPack([]PatternRule) error }:
			if err := pd.SetPatternPack(rules); err != nil {
				errs = append(errs, &DetectorError{Detector: d.Name(), Err: fmt.Errorf("pattern pack not applied: %w", err)})
			}
		case interface{ SetPatternPack([]PatternRule) }:
			pd.SetPatternPack(rules)
		}
	}
	c.packErrs.Store(errs)
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
	if _, hit := set[strings.ToLower(span)]; hit {
		return true
	}
	// A term is ruled on as it reads, not as it is encoded: support%40example.com.
	if dec, _, ok := normalizedView(span); ok {
		_, hit := set[strings.ToLower(dec)]
		return hit
	}
	return false
}

// Run returns merged, guard-validated spans and an error joining
// (errors.Join) every failure, nil when there was none. On any error the
// spans may be incomplete; see Chain. Each engine's failure is a
// *DetectorError — find one with errors.As. A Chain with no Detectors adds
// ErrNoDetectors, and a done ctx surfaces as ctx's error inside the floor's
// DetectorError; both match with errors.Is.
//
// A span with offsets outside text is dropped and reported as its engine's
// DetectorError wrapping ErrSpanOutOfRange. Kept, it would panic in a type guard, or merge with valid neighbours
// into a union Mask cannot apply — leaving all of them in the clear.
//
// A span the allow list suppresses also takes with it every span of the same
// type inside it: a decoded reading of the allowed term (support+billing@…
// read with '+' as a space) is the same characters, not another value. A span
// that reaches outside it, or is of another type, stands.
func (c *Chain) Run(ctx context.Context, text string) ([]Span, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	var all, allowed []Span
	var errs []error
	if pe, _ := c.packErrs.Load().([]error); len(pe) > 0 {
		errs = append(errs, pe...)
	}
	detectors := c.Detectors
	if len(detectors) == 0 {
		detectors = []Detector{NewRegex()}
		errs = append(errs, ErrNoDetectors)
	}
	off := typeSet(c.Disable)
	for _, d := range detectors {
		var spans []Span
		var err error
		if rd, ok := d.(rawDetector); ok {
			if rx, isRegex := d.(*Regex); isRegex && len(off) > 0 {
				rd = rx.without(off) // never scan for a type that is dropped
			}
			// The in-process floor is linear time and is what must not come back
			// partly read; only the caller's own context stops it.
			spans, err = rd.detectRaw(ctx, text)
		} else {
			dctx, cancel := context.WithTimeout(ctx, timeout)
			spans, err = d.Detect(dctx, text)
			cancel()
		}
		if err != nil {
			// Keep what it found before failing: masking more is the safe side.
			errs = append(errs, &DetectorError{Detector: d.Name(), Err: err})
		}
		bad := 0
		for _, sp := range spans {
			if sp.Start == sp.End || off[sp.Type] {
				continue // claims nothing, or nothing the caller wants
			}
			if !sp.within(text) {
				bad++
				continue
			}
			if guard, ok := typeGuards[sp.Type]; ok && !sp.checked && !guard(text, sp.Start, sp.End) {
				continue
			}
			if c.allowed(sp.Type, text[sp.Start:sp.End]) {
				allowed = append(allowed, sp)
				continue
			}
			all = append(all, sp)
		}
		if bad > 0 {
			errs = append(errs, &DetectorError{Detector: d.Name(), Err: fmt.Errorf("dropped %d span(s): %w", bad, ErrSpanOutOfRange)})
		}
	}
	if len(allowed) > 0 {
		kept := all[:0]
		for _, sp := range all {
			if !insideAny(sp, allowed) {
				kept = append(kept, sp)
			}
		}
		all = kept
	}
	return Merge(all), errors.Join(errs...)
}

// typeSet returns types as a set, nil when there are none.
func typeSet(types []string) map[string]bool {
	if len(types) == 0 {
		return nil
	}
	set := make(map[string]bool, len(types))
	for _, t := range types {
		set[t] = true
	}
	return set
}

// insideAny reports whether sp lies within a span of its own type in spans.
func insideAny(sp Span, spans []Span) bool {
	for _, a := range spans {
		if a.Type == sp.Type && a.Start <= sp.Start && sp.End <= a.End {
			return true
		}
	}
	return false
}

// within reports whether sp is a non-empty span inside text.
func (sp Span) within(text string) bool {
	return 0 <= sp.Start && sp.Start < sp.End && sp.End <= len(text)
}

// Merge sorts spans and collapses overlaps: the union wins the extent, the
// higher confidence wins type and provenance. On equal confidence the claim
// that starts first wins, then the longer, then the lower Type in byte order,
// so the result does not depend on the order of spans. It sorts and
// overwrites spans in place and returns a prefix of it.
func Merge(spans []Span) []Span {
	if len(spans) < 2 {
		return spans
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start != spans[j].Start {
			return spans[i].Start < spans[j].Start
		}
		if spans[i].End != spans[j].End {
			return spans[i].End > spans[j].End
		}
		// Ties broken so a merged span's Type is the same whatever order the
		// claims came in.
		if spans[i].Confidence != spans[j].Confidence {
			return spans[i].Confidence > spans[j].Confidence
		}
		if spans[i].Type != spans[j].Type {
			return spans[i].Type < spans[j].Type
		}
		return spans[i].Detector < spans[j].Detector
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
