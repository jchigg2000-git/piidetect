package piidetect

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
)

// Regex is the in-process deterministic floor: RE2 (linear-time, safe on
// hostile input) recognizers plus a hot-swappable pattern-pack overlay the
// flywheel extends at runtime.
//
// Deliberate v0 misses (they are the flywheel's first demo): bare 9-digit
// SSNs, bare MRNs without a prefix, non-zero-padded or ISO dates with no
// birth label in front, and all free-text PHI (names, addresses — Presidio's
// job).
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

// confidence is the rule's score, 0.75 when unset. Both engines use it: sent to
// Presidio as 0, an unscored rule's hits would all fall under the score gate.
func (r PatternRule) confidence() float64 {
	if r.Confidence == 0 {
		return 0.75
	}
	return r.Confidence
}

type recognizer struct {
	typ        string
	re         *regexp.Regexp
	confidence float64
	// validate rejects a raw regex hit using surrounding context (RE2 has no
	// lookarounds, so trap rejection lives here). nil accepts every hit.
	validate func(text string, start, end int) bool
	// trim, when set, runs before validate and cuts a greedy hit back to the
	// value's real end, rejecting it if there is none — so a token that
	// happens to share the value's shape ("… 7034 BIC") cannot void the match.
	trim func(text string, start, end int) (int, bool)
}

func builtinRecognizers() []recognizer {
	return []recognizer{
		{typ: "EMAIL", confidence: 0.95,
			re: regexp.MustCompile(`\b[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)},
		{typ: "SSN", confidence: 0.9,
			re:       regexp.MustCompile(`\b\d{3}[- ]\d{2}[- ]\d{4}\b`),
			validate: notHyphenAdjacent},
		// NANP. No \b on either side: nanpValid bounds the hit by non-digits
		// instead, so "Tel415-555-0173" and "…0173x204" still count.
		{typ: "PHONE", confidence: 0.85,
			re:       regexp.MustCompile(`(\+1[-. ]?)?(\(\d{3}\)[-. ]?|\d{3}[-. ])\d{3}[-. ]\d{4}`),
			validate: nanpValid},
		// NANP with a bare trunk 1 ("1-800-555-0199"). Separate from the rule
		// above so that a number merely ending in 1 ("Apt 21 415-555-0173")
		// cannot pull the trunk into the phone and void it.
		{typ: "PHONE", confidence: 0.85,
			re:       regexp.MustCompile(`\b1(?:[-. ]?\(\d{3}\)[-. ]?|[-. ]\d{3}[-. ])\d{3}[-. ]\d{4}`),
			validate: nanpValid},
		{typ: "PHONE", confidence: 0.85,
			re: regexp.MustCompile(`\+[1-9]\d{9,14}\b`)},
		// International numbers as printed: country code, a separator, then
		// 8–12 national digits in any grouping. +1 belongs to NANP above, and
		// single-digit codes other than 7 are excluded so "zip+4 94110-1234"
		// is not a phone.
		{typ: "PHONE", confidence: 0.85,
			re: regexp.MustCompile(`\+(?:7|[2-9]\d{1,2})[- ](?:\(0\)[- ]?)?\d(?:[- ]?\d){7,11}\b`)},
		{typ: "CREDIT_CARD", confidence: 0.9,
			re:       regexp.MustCompile(`\b\d(?:[- ]?\d){12,18}\b`),
			validate: luhnValid},
		// The standard card layouts on their own. The rule above is greedy and
		// runs on into a trailing expiry or CVV ("4111 1111 1111 1111 12/27"),
		// then fails Luhn on the whole; this one stops at the card.
		{typ: "CREDIT_CARD", confidence: 0.9,
			re:       regexp.MustCompile(`\b(?:\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}|\d{4}[- ]\d{6}[- ]\d{4,5}|\d{13,19})\b`),
			validate: luhnValid},
		{typ: "IP", confidence: 0.8,
			re:       regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			validate: validIP},
		// Electronic format, any case.
		{typ: "IBAN", confidence: 0.9,
			re:       regexp.MustCompile(`(?i)\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`),
			validate: ibanValid},
		// Paper format, grouped in fours — how an IBAN is printed on an
		// invoice. Uppercase only: lowercase four-letter words would flood it.
		{typ: "IBAN", confidence: 0.9,
			re:   regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?\b`),
			trim: ibanGrouped},
		// The label, optionally "#", "No." or "Number", then any horizontal
		// space around one optional separator. A line break is crossed only
		// after an explicit separator ("MRN:\n4481920"), so a table header
		// ending in "MRN" never claims the first number of the next row.
		// Quotes admit JSON and dict keys; mrnLabelStart stands in for a
		// leading \b so that snake_case keys (patient_mrn) count too.
		{typ: "MRN", confidence: 0.85,
			re:       regexp.MustCompile(`(?i)MRN(?:[ \t\x{A0}]*(?:#|No\.?|Number))?["']?[ \t\x{A0}]*(?:[-:=#>][ \t\x{A0}]*(?:\r?\n[ \t\x{A0}]*)?)?["']?\d{6,10}\b`),
			validate: mrnLabelStart},
		{typ: "DOB", confidence: 0.7,
			re: regexp.MustCompile(`\b(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])/(19|20)\d{2}\b`)},
		// Dates of birth as people actually write them: unpadded, "-" or "."
		// separators, day or month first, two-digit years, ISO, month names.
		// Unlabeled, these shapes are overwhelmingly appointment, invoice and
		// log dates, so dobCue requires a birth label right before the value.
		{typ: "DOB", confidence: 0.7,
			re: regexp.MustCompile(`(?i)\b(?:` +
				`(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|[12]\d|3[01])[-/.](?:19|20)?\d{2}` +
				`|(?:19|20)\d{2}-(?:0?[1-9]|1[0-2])-(?:0?[1-9]|[12]\d|3[01])` +
				`|(?:0?[1-9]|[12]\d|3[01])\.? (?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?,? (?:19|20)\d{2}` +
				`|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.? (?:0?[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?,? (?:19|20)\d{2}` +
				`)\b`),
			validate: dobCue},
	}
}

// builtins is compiled once and shared by every Regex (a *regexp.Regexp is
// safe for concurrent use), so New() per call does not recompile them.
var builtins = builtinRecognizers()

func NewRegex() *Regex {
	r := &Regex{}
	base := builtins
	r.compiled.Store(&base)
	return r
}

func (r *Regex) Name() string { return "regex" }

// SetPatternPack recompiles builtin + pack rules and atomically swaps the
// recognizer set — the flywheel hot-reload path, no restart. Non-regex kinds
// (deny lists, thresholds) are Presidio configuration and are skipped here.
func (r *Regex) SetPatternPack(rules []PatternRule) error {
	next := slices.Clone(builtins)
	for _, rule := range rules {
		if !rule.isRegex() {
			continue
		}
		re, err := regexp.Compile(rule.Regex)
		if err != nil {
			return fmt.Errorf("pattern %s (%s): %w", rule.ID, rule.Type, err)
		}
		next = append(next, recognizer{typ: rule.Type, re: re, confidence: rule.confidence()})
	}
	r.compiled.Store(&next)
	return nil
}

// Detect returns the recognizers' hits merged, so they can go straight to
// Mask. A Chain uses detectRaw instead: see rawDetector.
func (r *Regex) Detect(ctx context.Context, text string) ([]Span, error) {
	spans, err := r.detectRaw(ctx, text)
	return Merge(spans), err
}

func (r *Regex) detectRaw(_ context.Context, text string) ([]Span, error) {
	var spans []Span
	for _, rec := range *r.compiled.Load() {
		for _, loc := range rec.re.FindAllStringIndex(text, -1) {
			start, end := loc[0], loc[1]
			if rec.trim != nil {
				var ok bool
				if end, ok = rec.trim(text, start, end); !ok {
					continue
				}
			}
			if rec.validate != nil && !rec.validate(text, start, end) {
				continue
			}
			spans = append(spans, Span{
				Start: start, End: end, Type: rec.typ,
				Confidence: rec.confidence, Detector: "regex",
			})
		}
	}
	return spans, nil
}

// notHyphenAdjacent rejects hits glued to a hyphenated identifier on either
// side — the ORD-123-45-6789 order-number trap. A hyphen that is not itself
// glued to a letter or digit ("--" standing in for a dash, "- " before a
// note) is punctuation, not part of an identifier, and does not count.
func notHyphenAdjacent(text string, start, end int) bool {
	if start > 0 && text[start-1] == '-' && (start < 2 || isAlnum(text[start-2])) {
		return false
	}
	if end < len(text) && text[end] == '-' && (end+1 >= len(text) || isAlnum(text[end+1])) {
		return false
	}
	return true
}

// nanpValid bounds a NANP hit by non-digits on both sides, so the tail of a
// longer digit run ("Ref 98765-432-1098") is not a phone.
func nanpValid(text string, start, end int) bool {
	if start > 0 && isDigit(text[start-1]) {
		return false
	}
	if end < len(text) && isDigit(text[end]) {
		return false
	}
	return notHyphenAdjacent(text, start, end)
}

// mrnLabelStart rejects an MRN label that is the tail of a longer word or
// number (EMRN, SMRN). Underscore and punctuation are fine: patient_mrn.
func mrnLabelStart(text string, start, _ int) bool {
	return start == 0 || !isAlnum(text[start-1])
}

// dobCues are the labels that make a bare date a date of birth, matched
// against the text immediately before it. The short ones must start a word
// (stillbirth, newborn); the compounds may be glued to a camelCase or
// snake_case prefix (patientBirthDate).
var dobCues = []struct {
	cue       string
	wordStart bool
}{
	{"dob", true}, {"d.o.b", true}, {"birth", true}, {"born", true}, {"born on", true},
	{"birthdate", false}, {"birth date", false}, {"birth_date", false},
	{"dateofbirth", false}, {"birthday", false},
}

func dobCue(text string, start, _ int) bool {
	lo := max(start-40, 0)
	before := strings.TrimRight(strings.ToLower(text[lo:start]), " \t:#.=-\"'(\u00a0")
	for _, c := range dobCues {
		if !strings.HasSuffix(before, c.cue) {
			continue
		}
		i := len(before) - len(c.cue)
		if !c.wordStart || i == 0 || !isAlpha(before[i-1]) {
			return true
		}
	}
	return false
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

// validIP confirms a dotted quad — octet range and no leading zeros, both of
// which netip enforces — that is not four fields of a longer dotted run such
// as an OID (1.3.6.1.4.1.311). The regex floor only claims dotted quads, but
// as a type guard this also sees other engines' IPv6 and CIDR spans.
func validIP(text string, start, end int) bool {
	s := text[start:end]
	if strings.Contains(s, "/") {
		_, err := netip.ParsePrefix(s)
		return err == nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	if addr.Is4() {
		if start > 1 && text[start-1] == '.' && isDigit(text[start-2]) {
			return false
		}
		if end+1 < len(text) && text[end] == '.' && isDigit(text[end+1]) {
			return false
		}
	}
	return true
}

// ibanValid checks the ISO 13616 mod-97 check digits on the electronic or the
// paper (space-grouped) form, in any case. A registered country must also have
// its registered length. The spaced and lowercase forms are accepted only for
// registered countries, which is what keeps lowercase hex digests out.
func ibanValid(text string, start, end int) bool {
	raw := text[start:end]
	s := strings.ToUpper(strings.ReplaceAll(raw, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	n, registered := ibanLengths[s[:2]]
	if registered && len(s) != n {
		return false
	}
	if !registered && s != raw {
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

// ibanGrouped cuts a paper-format hit back to its country's registered length,
// which must fall on a group boundary, and validates what is left.
func ibanGrouped(text string, start, end int) (int, bool) {
	n, ok := ibanLengths[text[start:start+2]]
	if !ok {
		return 0, false
	}
	count := 0
	for i := start; i < end; i++ {
		if text[i] == ' ' {
			continue
		}
		count++
		if count == n {
			if i+1 < end && text[i+1] != ' ' {
				return 0, false
			}
			return i + 1, ibanValid(text, start, i+1)
		}
	}
	return 0, false
}

// ibanLengths is the SWIFT IBAN registry (ISO 13616) — country code to total
// length — plus the countries that use IBANs without being registered.
var ibanLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
	"BH": 22, "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24,
	"DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18,
	"FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27,
	"GT": 28, "HN": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26,
	"IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20,
	"LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20,
	"MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24,
	"PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33, "SA": 24,
	"SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25,
	"SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
	"YE": 30,
	// Unregistered but in use.
	"AO": 25, "BF": 28, "BJ": 28, "CF": 27, "CG": 27, "CI": 28, "CM": 27, "CV": 25,
	"DZ": 26, "GA": 27, "GQ": 27, "GW": 25, "IR": 26, "KM": 27, "MA": 28, "MG": 27,
	"ML": 28, "MZ": 25, "NE": 28, "SN": 28, "TD": 27, "TG": 28,
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }
