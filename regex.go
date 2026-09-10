package piidetect

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
)

// Regex is the in-process deterministic floor: RE2 (linear-time, safe on
// hostile input) recognizers plus a hot-swappable pattern-pack overlay the
// flywheel extends at runtime.
//
// Deliberate v0 misses (they are the flywheel's first demo): bare 9-digit
// SSNs, bare MRNs without a prefix, and all free-text PHI (names, addresses —
// Presidio's job).
type Regex struct {
	compiled atomic.Pointer[[]recognizer]
}

// PatternRule is one flywheel-approved addition to the built-in recognizers.
// Kind selects how the rule is applied: "" / "regex" compiles here; "deny_list"
// and "threshold" are Presidio-side configuration this engine skips.
type PatternRule struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	Kind       string   `json:"kind,omitempty"`
	Regex      string   `json:"regex,omitempty"`
	DenyList   []string `json:"deny_list,omitempty"`
	AllowList  []string `json:"allow_list,omitempty"`
	Threshold  float64  `json:"threshold,omitempty"`
	Context    []string `json:"context,omitempty"`
	Confidence float64  `json:"confidence,omitempty"`
}

func (r PatternRule) isRegex() bool { return r.Kind == "" || r.Kind == "regex" }

type recognizer struct {
	typ        string
	re         *regexp.Regexp
	confidence float64
	// validate rejects a raw regex hit using surrounding context (RE2 has no
	// lookarounds, so trap rejection lives here). nil accepts every hit.
	validate func(text string, start, end int) bool
}

func builtinRecognizers() []recognizer {
	return []recognizer{
		{typ: "EMAIL", confidence: 0.95,
			re: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)},
		{typ: "SSN", confidence: 0.9,
			re:       regexp.MustCompile(`\b\d{3}[- ]\d{2}[- ]\d{4}\b`),
			validate: notHyphenAdjacent},
		{typ: "PHONE", confidence: 0.85,
			re:       regexp.MustCompile(`(\+1[-. ]?)?(\(\d{3}\)[-. ]?|\d{3}[-. ])\d{3}[-. ]\d{4}\b`),
			validate: notHyphenAdjacent},
		{typ: "PHONE", confidence: 0.85,
			re: regexp.MustCompile(`\+[1-9]\d{9,14}\b`)},
		{typ: "CREDIT_CARD", confidence: 0.9,
			re:       regexp.MustCompile(`\b\d(?:[- ]?\d){12,18}\b`),
			validate: luhnValid},
		{typ: "IP", confidence: 0.8,
			re:       regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			validate: validOctets},
		{typ: "IBAN", confidence: 0.9,
			re:       regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`),
			validate: ibanMod97},
		{typ: "MRN", confidence: 0.85,
			re: regexp.MustCompile(`(?i)\bMRN[-: ]?\d{6,10}\b`)},
		{typ: "DOB", confidence: 0.7,
			re: regexp.MustCompile(`\b(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])/(19|20)\d{2}\b`)},
	}
}

func NewRegex() *Regex {
	r := &Regex{}
	base := builtinRecognizers()
	r.compiled.Store(&base)
	return r
}

func (r *Regex) Name() string { return "regex" }

// SetPatternPack recompiles builtin + pack rules and atomically swaps the
// recognizer set — the flywheel hot-reload path, no restart. Non-regex kinds
// (deny lists, thresholds) are Presidio configuration and are skipped here.
func (r *Regex) SetPatternPack(rules []PatternRule) error {
	next := builtinRecognizers()
	for _, rule := range rules {
		if !rule.isRegex() {
			continue
		}
		re, err := regexp.Compile(rule.Regex)
		if err != nil {
			return fmt.Errorf("pattern %s (%s): %w", rule.ID, rule.Type, err)
		}
		conf := rule.Confidence
		if conf == 0 {
			conf = 0.75
		}
		next = append(next, recognizer{typ: rule.Type, re: re, confidence: conf})
	}
	r.compiled.Store(&next)
	return nil
}

func (r *Regex) Detect(_ context.Context, text string) ([]Span, error) {
	var spans []Span
	for _, rec := range *r.compiled.Load() {
		for _, loc := range rec.re.FindAllStringIndex(text, -1) {
			if rec.validate != nil && !rec.validate(text, loc[0], loc[1]) {
				continue
			}
			spans = append(spans, Span{
				Start: loc[0], End: loc[1], Type: rec.typ,
				Confidence: rec.confidence, Detector: "regex",
			})
		}
	}
	return Merge(spans), nil
}

// notHyphenAdjacent rejects hits glued to a hyphenated identifier on either
// side — the ORD-123-45-6789 order-number trap.
func notHyphenAdjacent(text string, start, end int) bool {
	if start > 0 && text[start-1] == '-' {
		return false
	}
	if end < len(text) && text[end] == '-' {
		return false
	}
	return true
}

func luhnValid(text string, start, end int) bool {
	if !notHyphenAdjacent(text, start, end) {
		return false
	}
	var digits []int
	for _, c := range text[start:end] {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

func validOctets(text string, start, end int) bool {
	for _, part := range strings.Split(text[start:end], ".") {
		if len(part) > 1 && part[0] == '0' {
			return false
		}
		n := 0
		for _, c := range part {
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

// ibanMod97 validates the ISO 13616 check digits, killing lookalike FPs.
func ibanMod97(text string, start, end int) bool {
	s := text[start:end]
	if len(s) < 15 {
		return false
	}
	rearranged := s[4:] + s[:4]
	rem := 0
	for _, c := range rearranged {
		switch {
		case c >= '0' && c <= '9':
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			n := int(c-'A') + 10
			rem = (rem*100 + n) % 97
		default:
			return false
		}
	}
	return rem == 1
}
