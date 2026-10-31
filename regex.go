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
// Deliberate v0 misses (they are the flywheel's first demo): 9-digit SSNs
// and 10-digit phone numbers with no label in front, bare MRNs without a
// label, non-zero-padded or ISO dates with no birth label in front, and all
// free-text PHI (names, addresses — Presidio's job).
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
	// find, when set, replaces re: the recognizer scans by hand.
	find func(text string) [][]int
	// findRE is the regex every find hit lies within a match of, if any; its
	// required literals gate find the way re's gate a plain recognizer.
	findRE *regexp.Regexp
	// cues, when set, are the labels one of which must sit right before a
	// hit (labelledBy), checked after validate.
	cues []cue
	// needs are literals the text must hold for the recognizer to match at
	// all, derived from re and cues by withNeeds: scan skips it otherwise.
	needs needs
	// cuts are the ASCII bytes no hit holds, so the normalized view can be
	// re-read in windows (window.go). withNeeds derives them from re; a find
	// recognizer declares its own, and without them reads the whole view.
	cuts *cutSet
}

func builtinRecognizers() []recognizer {
	recs := []recognizer{
		// Letters are Latin, Greek or Cyrillic with their combining marks, so
		// müller@münchen.de is covered whole: RE2's \b is ASCII-only, and an
		// ASCII class left "mü" in front of the placeholder. Scripts written
		// without spaces (CJK, Thai) are left out, or the address would absorb
		// the words around it. The first character must be a letter, digit or
		// underscore, which a leading \b used to enforce.
		{typ: "EMAIL", confidence: 0.95,
			re:       regexp.MustCompile(`[` + emailLetters + `0-9_][` + emailLetters + `\p{M}0-9._%+'-]*@[` + emailLetters + `\p{M}0-9.-]+\.[` + emailLetters + `\p{M}]{2,}`),
			validate: emailValid},
		// Spaced only ("123 45 6789") it needs an SSN label right before it:
		// a status, size and byte count in an access log ("200 12 4096") or a
		// form body's 123+45+6789 has the same shape.
		{typ: "SSN", confidence: 0.9,
			re:       regexp.MustCompile(`\b\d{3}[- ]\d{2}[- ]\d{4}\b`),
			validate: ssnShapeValid},
		// An unformatted SSN, but only right after an SSN label ("SSN:
		// 078051120", {"ssn":"078051120"}): unlabeled, nine digits are far more
		// often an order or account number.
		{typ: "SSN", confidence: 0.85,
			re:       regexp.MustCompile(`\b\d{9}\b`),
			validate: ssnValid, cues: ssnCues},
		// NANP. No \b on either side: nanpValid bounds the hit by non-digits
		// instead, so "Tel415-555-0173" and "…0173x204" still count. Spaced
		// only ("415 555 0173") it needs a phone label or "call"/"text" right
		// before it, as a list of sizes ("512 768 1024") has the same shape.
		{typ: "PHONE", confidence: 0.85,
			re:       regexp.MustCompile(`(\+1[-. ]?)?(\(\d{3}\)[-. ]?|\d{3}[-. ])\d{3}[-. ]\d{4}`),
			validate: phoneShapeValid},
		// NANP with a bare trunk 1 ("1-800-555-0199"). Separate from the rule
		// above so that a number merely ending in 1 ("Apt 21 415-555-0173")
		// cannot pull the trunk into the phone and void it.
		{typ: "PHONE", confidence: 0.85,
			re:       regexp.MustCompile(`\b1(?:[-. ]?\(\d{3}\)[-. ]?|[-. ]\d{3}[-. ])\d{3}[-. ]\d{4}`),
			validate: phoneShapeValid},
		// An unformatted NANP number, but only right after a phone label
		// ("Phone: 4155550173", {"mobile":"4155550173"}), for the same reason
		// as the unformatted SSN above.
		{typ: "PHONE", confidence: 0.8,
			re:       regexp.MustCompile(`\b1?\d{10}\b`),
			validate: nanpValid, cues: phoneCues},
		// E.164. A +1 number is NANP: exactly ten digits after the +1, passing
		// nanpValid, so a signed counter (delta=+1500000000, +1727049600007)
		// is not a phone.
		{typ: "PHONE", confidence: 0.85,
			re:       regexp.MustCompile(`\+[1-9]\d{9,14}\b`),
			validate: e164Valid},
		// International numbers as printed: country code, a separator, then
		// 8–12 national digits in any grouping, or a bracketed area code or
		// trunk 0 and at least 6 more ("+55 (11) 91234-5678", "+44 (0)20 …").
		// +1 belongs to NANP above, and single-digit codes other than 7 are
		// excluded so "zip+4 94110-1234" is not a phone.
		{typ: "PHONE", confidence: 0.85,
			re: regexp.MustCompile(`\+(?:7|[2-9]\d{1,2})(?:[- ]?\(\d{1,4}\)[- ]?\d(?:[- ]?\d){5,10}|[- ]\d(?:[- ]?\d){7,11})\b`)},
		// Cards as printed, never any spacing of digits: a list of ids
		// ("ids 42 17 88 93 12 55 61") is not a card. This rule is the 19-digit
		// layout, 4-4-4-4-3.
		{typ: "CREDIT_CARD", confidence: 0.9,
			re:       regexp.MustCompile(`\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{3}\b`),
			validate: luhnValid},
		// The other layouts: 4-4-4-4, Amex 4-6-5, Diners 4-6-4, and 13–19
		// digits unformatted. Kept apart from the rule above so that a CVV after
		// a 16-digit card ("4111 1111 1111 1111 123") cannot pull the card into
		// a 19-digit run that fails Luhn; this one stops at the card.
		{typ: "CREDIT_CARD", confidence: 0.9,
			re:       regexp.MustCompile(`\b(?:\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}|\d{4}[- ]\d{6}[- ]\d{4,5}|\d{13,19})\b`),
			validate: luhnValid},
		{typ: "IP", confidence: 0.8,
			re:       regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			validate: validIP},
		// IPv6, scanned by hand: see ipv6.go.
		{typ: "IP", confidence: 0.8, find: findIPv6, cuts: ipv6Cuts},
		// Electronic format, any case.
		{typ: "IBAN", confidence: 0.9,
			re:       regexp.MustCompile(`(?i)\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`),
			validate: ibanValid},
		// Paper format, grouped in fours — how an IBAN is printed on an
		// invoice. Uppercase only: lowercase four-letter words would flood it.
		{typ: "IBAN", confidence: 0.9,
			re:   regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?\b`),
			trim: ibanGrouped},
		// The label ("MRN", "Medical Record", "Med Rec"), optionally "#",
		// "No.", "Num" or "Number", or "MR#" (the "#" required, so the title
		// "Mr" before a number never counts), then optionally "is" or "was"
		// ("MRN is 4481920"), then any horizontal
		// space (tab or any Unicode space, so U+2009 and U+3000 count) around
		// an optional separator of one or two characters ("MRN--4481920",
		// "MRN:-4481920"). A line break is crossed only
		// after an explicit separator ("MRN:\n4481920"), so a table header
		// ending in "MRN" never claims the first number of the next row.
		// Quotes admit JSON and dict keys; mrnLabelStart stands in for a
		// leading \b so that snake_case keys (patient_mrn) count too.
		// The value may carry a one- or two-letter prefix (E1234567) and
		// internal hyphens (12-345-678); see findMRN.
		{typ: "MRN", confidence: 0.85, find: findMRN, findRE: mrnRE, cuts: regexCuts(mrnRE),
			validate: mrnLabelStart},
		// MM/DD/YYYY anywhere, except where it is plainly not a birth date: a
		// log timestamp or one end of a date range (see dobNotEvent).
		{typ: "DOB", confidence: 0.7,
			re:       regexp.MustCompile(`\b(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])/(19|20)\d{2}\b`),
			validate: dobNotEvent},
		// Dates of birth as people actually write them: unpadded, "-" or "."
		// separators, day or month first, two-digit years, ISO, month names
		// (14-Mar-1985, 14th March 1985), an ISO date with its time and zone
		// (1985-03-14T00:00:00Z, as Go marshals a time.Time) and compact
		// YYYYMMDD (19850314).
		// Unlabeled, these shapes are overwhelmingly appointment, invoice and
		// log dates, so dobCue requires a birth label right before the value.
		// The digit-led shapes open without \b so a date glued to its cue
		// ("DOB03/14/1985", "dob1985-03-14") is found; dobCue rejects a
		// digit before the value, which \b used to.
		{typ: "DOB", confidence: 0.7,
			re: regexp.MustCompile(`(?i)(?:` +
				`(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|[12]\d|3[01])[-/.](?:19|20)?\d{2}` +
				`|(?:19|20)\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])` + isoTimeTail +
				`|(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])` +
				`|(?:0?[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?(?:\.? |-)(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*(?:\.?,? |-)(?:19|20)?\d{2}` +
				`|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.? (?:0?[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?,? (?:19|20)\d{2}` +
				`)\b`),
			cues: dobCues},
		// Medicare Beneficiary Identifier as printed on the card,
		// 1EG4-TE5-MK73, anywhere. CMS issues it uppercase; a lowercase or
		// mixed-case one needs an MBI or Medicare label right before it
		// (mbiDashedValid), as a lowercase hex key can share the shape.
		{typ: "MBI", confidence: 0.85,
			re:       regexp.MustCompile(`(?i)\b` + mbiHead + `-` + mbiMid + `-` + mbiTail + `\b`),
			validate: mbiDashedValid},
		// Unformatted, 1EG4TE5MK73, only right after an MBI or Medicare
		// label ("MBI: …", {"medicareId":"…"}), in either case: unlabelled,
		// eleven uppercase letters and digits are as often a request or
		// trace ID that happens to fit.
		{typ: "MBI", confidence: 0.85,
			re:       regexp.MustCompile(`(?i)\b` + mbiHead + mbiMid + mbiTail + `\b`),
			validate: mbiValid, cues: mbiCues},
	}
	for i := range recs {
		recs[i] = recs[i].withNeeds()
	}
	return recs
}

// retinaAsset matches the tail of an image file name that has the shape of an
// address: logo@2x.png, icon@3x.jpg.
var retinaAsset = regexp.MustCompile(`(?i)@[1-9]x\.(?:png|jpe?g|gif|webp|svg|avif|heic|bmp|ico|tiff?)$`)

// emailValid rejects the high-density-display asset names (logo@2x.png) that
// HTML, CSS and build output are full of: the "domain" 2x.png has an image
// extension for a TLD. Image extensions are not TLDs, so no address is lost.
//
// It also rejects the two shapes code gives an address: a method call
// (A@np.linalg.inv(B), Python's matrix-multiply operator) and an SSH or scp
// remote (git@github.com:org/repo.git). For the remote, the ":" must be
// followed, with no space, by a path: a run holding a "/" or ending ".git".
// An address that merely ends a clause ("email jane@example.org: call her",
// "user=jane@example.org:login") is still an address.
func emailValid(text string, start, end int) bool {
	if retinaAsset.MatchString(text[start:end]) {
		return false
	}
	if end < len(text) && text[end] == '(' {
		return false
	}
	if end+1 < len(text) && text[end] == ':' {
		rest := text[end+1:]
		if i := strings.IndexAny(rest, emailPathEnd); i >= 0 {
			rest = rest[:i]
		}
		if strings.Contains(rest, "/") || strings.HasSuffix(rest, ".git") {
			return false
		}
	}
	return true
}

// emailPathEnd ends the path emailValid reads after an address's ':'. The
// windowed read of the normalized view (window.go) reaches back to it.
const emailPathEnd = " \t\r\n\"'<>,;)"

func isEmailPathEnd(c byte) bool { return strings.IndexByte(emailPathEnd, c) >= 0 }

// emailLetters are the scripts an email address is matched in; see EMAIL.
const emailLetters = `\p{Latin}\p{Greek}\p{Cyrillic}`

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

// without returns a Regex reading with r's current recognizers minus those of
// the off types, so a type a Chain drops is never scanned for at all.
func (r *Regex) without(off map[string]bool) *Regex {
	recs := builtins
	if p := r.compiled.Load(); p != nil {
		recs = *p
	}
	kept := make([]recognizer, 0, len(recs))
	for _, rec := range recs {
		if !off[rec.typ] {
			kept = append(kept, rec)
		}
	}
	v := &Regex{}
	v.compiled.Store(&kept)
	return v
}

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
		next = append(next, recognizer{typ: rule.Type, re: re, confidence: rule.confidence()}.withNeeds())
	}
	r.compiled.Store(&next)
	return nil
}

// Detect returns the recognizers' hits merged, so they can go straight to
// Mask. A Chain uses detectRaw instead: see rawDetector.
//
// A zero Regex reads with the built-in recognizers, as NewRegex does. Detect
// stops between recognizers once ctx is done and returns the hits found so far
// with ctx's error. Those are not every value in text: a caller must treat an
// error as failure (mask the whole text, or drop it), not send on what Mask
// makes of a partial result.
func (r *Regex) Detect(ctx context.Context, text string) ([]Span, error) {
	spans, err := r.detectRaw(ctx, text)
	return Merge(spans), err
}

// detectRaw reads the text as given and, when it carries JSON escapes,
// percent-encoding or look-alike punctuation, as normalized too. A span found only in the
// normalized text is judged there — the
// recognizer's own validator and the type guard, whose context checks need the
// decoded characters — then mapped back to the offsets of the text as given
// and marked checked, so the chain does not judge it a second time against
// escapes it cannot read.
//
// The normalized text is read only in windows around the bytes normalizing
// changed; window.go shows why that finds what a whole read would, less hits
// the read as given has already found.
func (r *Regex) detectRaw(ctx context.Context, text string) ([]Span, error) {
	return r.detect(ctx, text, true)
}

// detect is detectRaw, reading the whole normalized text unless windowed: the
// whole read is the reference the windowed one is tested against.
func (r *Regex) detect(ctx context.Context, text string, windowed bool) ([]Span, error) {
	recs := builtins
	if p := r.compiled.Load(); p != nil {
		recs = *p
	}
	spans := scan(ctx, recs, text)
	// Read as given, "Email:\njane.doe@example.org" holds the address
	// njane.doe@example.org. The value starts after the escape, and a span
	// that keeps its letter would mask it away: "Email:\[EMAIL]".
	kept := spans[:0]
	for _, sp := range spans {
		if sp.Start = pastEscape(text, sp.Start); sp.Start < sp.End {
			kept = append(kept, sp)
		}
	}
	spans = kept
	if err := ctx.Err(); err != nil {
		return spans, err
	}
	if dec, orig, ok := normalizedView(text); ok {
		var reach [][2]int // nil reads the whole view
		if windowed {
			reach = viewReach(dec, changedRuns(text, dec, orig))
		}
		for _, sp := range scanIn(ctx, recs, dec, reach) {
			if guard, has := typeGuards[sp.Type]; has && !guard(dec, sp.Start, sp.End) {
				continue
			}
			sp.Start, sp.End, sp.checked = orig[sp.Start], orig[sp.End], true
			spans = append(spans, sp)
		}
	}
	return spans, ctx.Err()
}

// pastEscape returns start, or the end of the JSON string escape whose
// backslash sits right before it (the n of \n, the u of ü). A backslash
// that is itself escaped (\\n) starts none.
func pastEscape(text string, start int) int {
	if start == 0 || text[start-1] != '\\' {
		return start
	}
	run := 1
	for run < start && text[start-1-run] == '\\' {
		run++
	}
	if run%2 == 0 {
		return start
	}
	if _, n := jsonEscape(text, start-1); n > 0 {
		return start - 1 + n
	}
	return start
}

// scan returns every validated hit of recs in text, unmerged. It stops before
// the next recognizer once ctx is done; the caller checks ctx.Err().
//
// A recognizer whose needs text does not meet is skipped: it could not match.
// The needs are checked against this same text, so on the normalized view a
// cue that was fullwidth or percent-encoded as given (ＭＲＮ, ssn%3A) counts.
func scan(ctx context.Context, recs []recognizer, text string) []Span {
	return scanIn(ctx, recs, text, nil)
}

// scanIn is scan reading only each recognizer's windows of text around reach
// (see windows), or all of text when reach is nil. Needs are still checked
// against the whole text, and every hit is judged in the whole text.
func scanIn(ctx context.Context, recs []recognizer, text string, reach [][2]int) []Span {
	var spans []Span
	var lower string
	for _, rec := range recs {
		if ctx.Err() != nil {
			break
		}
		if len(rec.needs) > 0 {
			if lower == "" {
				lower = asciiLower(text)
			}
			if !rec.needs.metBy(lower) {
				continue
			}
		}
		pieces := [][2]int{{0, len(text)}}
		if reach != nil {
			pieces = windows(text, reach, rec.cuts)
		}
		for _, piece := range pieces {
			from := piece[0]
			for _, loc := range rec.hits(text[from:piece[1]]) {
				start, end := from+loc[0], from+loc[1]
				if rec.validate != nil && !rec.validate(text, start, end) {
					continue
				}
				if rec.cues != nil && !labelledBy(text, start, rec.cues) {
					continue
				}
				spans = append(spans, Span{
					Start: start, End: end, Type: rec.typ,
					Confidence: rec.confidence, Detector: "regex",
				})
			}
		}
	}
	return spans
}

// hits returns rec's matches, each cut back by rec.trim when it has one. A
// trimmed search resumes where the value ended, not where the greedy match
// did, so the tail it cut off ("… 7034 NL91 ABNA …") can start the next value;
// a rejected match resumes one byte in. Either way the search restarts at a
// non-word byte or inside a letter pair, so \b still reads correctly there.
func (rec recognizer) hits(text string) [][]int {
	if rec.find != nil {
		return rec.find(text)
	}
	if rec.trim == nil {
		return rec.re.FindAllStringIndex(text, -1)
	}
	var hits [][]int
	for pos := 0; pos < len(text); {
		loc := rec.re.FindStringIndex(text[pos:])
		if loc == nil {
			break
		}
		start, end := pos+loc[0], pos+loc[1]
		if cut, ok := rec.trim(text, start, end); ok {
			hits = append(hits, []int{start, cut})
			pos = cut
		} else {
			pos = start + 1
		}
	}
	return hits
}

// notHyphenAdjacent rejects hits glued to a hyphenated identifier on either
// side — the ORD-123-45-6789 order-number trap. A hyphen that is not itself
// glued to a letter or digit ("--" standing in for a dash, "- " before a
// note) is punctuation, not part of an identifier, and does not count; nor
// does one joining a label to its value ("SSN-219-09-9999").
func notHyphenAdjacent(text string, start, end int) bool {
	if start > 0 && text[start-1] == '-' && (start < 2 || isAlnum(text[start-2])) && !hyphenLabel(text, start-1) {
		return false
	}
	if end < len(text) && text[end] == '-' && (end+1 >= len(text) || isAlnum(text[end+1])) {
		return false
	}
	return true
}

// hyphenLabels may be joined to their value by a hyphen without making it an
// identifier: SSN-219-09-9999 and Tel-415-555-0173 are labelled values,
// ORD-123-45-6789 is an order number.
var hyphenLabels = map[string]bool{
	"ssn": true, "tel": true, "phone": true, "fax": true, "cell": true,
	"mobile": true, "cc": true, "card": true, "mbi": true,
}

// hyphenLabel reports whether the hyphen at text[i] closes a whole word that
// is one of hyphenLabels.
func hyphenLabel(text string, i int) bool {
	j := i
	for j > 0 && i-j <= 6 && isAlpha(text[j-1]) {
		j--
	}
	if j > 0 && isAlnum(text[j-1]) {
		return false
	}
	return hyphenLabels[strings.ToLower(text[j:i])]
}

// ssnValid rejects numbers the SSA never issues (area 000 or 666, group 00,
// serial 0000) and hits glued to a hyphenated identifier. Area 9xx stays: it
// is the ITIN range, and Presidio's US_ITIN maps onto SSN.
func ssnValid(text string, start, end int) bool {
	d := digitsOf(text[start:end])
	if len(d) == 9 && (d[:3] == "000" || d[:3] == "666" || d[3:5] == "00" || d[5:] == "0000") {
		return false
	}
	return notHyphenAdjacent(text, start, end)
}

// ssnShapeValid is ssnValid for the formatted SSN rule, which also needs an
// SSN label before a value whose separators are all spaces. Dashed and mixed
// forms need none. Only the regex floor's own rule reads it: the type guard
// stays ssnValid.
func ssnShapeValid(text string, start, end int) bool {
	if !ssnValid(text, start, end) {
		return false
	}
	return !spaceSeparated(text[start:end]) || labelledBy(text, start, ssnCues)
}

// phoneShapeValid is nanpValid for the formatted NANP rules, which also need a
// phone cue before a number whose separators are all spaces. A dash, dot,
// bracket or "+1" in it is formatting enough.
func phoneShapeValid(text string, start, end int) bool {
	if !nanpValid(text, start, end) {
		return false
	}
	return !spaceSeparated(text[start:end]) || labelledBy(text, start, phoneCues)
}

// spaceSeparated reports whether s holds a space and every byte of it that is
// not a digit is one.
func spaceSeparated(s string) bool {
	spaced := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == ' ':
			spaced = true
		case !isDigit(s[i]):
			return false
		}
	}
	return spaced
}

// digitsOf returns the ASCII digits of s, in order.
func digitsOf(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			b = append(b, s[i])
		}
	}
	return string(b)
}

// nanpValid bounds a NANP hit by non-digits on both sides, so the tail of a
// longer digit run ("Ref 98765-432-1098") is not a phone, and requires the
// area code and exchange to start 2–9, as every assigned NANP number does
// ("123-456-7890" is a placeholder or an order number).
func nanpValid(text string, start, end int) bool {
	d := digitsOf(text[start:end])
	if len(d) == 11 {
		d = d[1:] // trunk 1 or +1
	}
	if len(d) != 10 || d[0] < '2' || d[3] < '2' {
		return false
	}
	if start > 0 && isDigit(text[start-1]) {
		return false
	}
	if end < len(text) && isDigit(text[end]) {
		return false
	}
	return notHyphenAdjacent(text, start, end)
}

// e164Valid accepts any E.164 number outside NANP. Inside it (+1) the number
// must be exactly ten digits after the +1 and pass nanpValid, so signed
// counters and offsets (delta=+1500000000, +1048576000, +1727049600007) are
// not phones.
func e164Valid(text string, start, end int) bool {
	if text[start+1] != '1' {
		return true
	}
	return end-start == 12 && nanpValid(text, start, end)
}

// mrnLabelStart rejects an MRN label that is the tail of a longer word or
// number (EMRN, SMRN). Underscore and punctuation are fine (patient_mrn), and
// so is a camelCase hump (patientMrn, PatientMRN).
func mrnLabelStart(text string, start, _ int) bool {
	if start == 0 || !isAlnum(text[start-1]) {
		return true
	}
	prev := text[start-1]
	return prev >= 'a' && prev <= 'z' && text[start] == 'M'
}

// isoTimeTail is the optional clock time and zone after an ISO date:
// "T00:00:00Z", " 00:00:00", "T09:30:00.123-05:00", " 00:00:00+00". Only the
// labelled DOB recognizer uses it, so the time is masked with the date.
const isoTimeTail = `(?:[T ](?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:[.,]\d{1,9})?)?(?:Z| ?[+-](?:[01]\d|2[0-3])(?::?[0-5]\d)?)?)?`

// mrnRE is the MRN label (MR only with its #, never the title), an optional
// is or was, its separator, and the value as group 1: an
// optional one- or two-letter prefix, then digit groups joined by single
// hyphens. No spaces inside the value, which would swallow a count after it.
var mrnRE = regexp.MustCompile(`(?i)(?:(?:MRN|medical[\t\p{Zs}_-]*record|med\.?[\t\p{Zs}_-]*rec\.?)(?:[\t\p{Zs}_]*(?:#|No\.?|Num(?:ber)?))?|MR#)(?:[\t\p{Zs}]+(?:is|was)\b)?["']?[\t\p{Zs}]*(?:[-:=#>]{1,2}[\t\p{Zs}]*(?:\r?\n[\t\p{Zs}]*)?)?["']?((?:[A-Z]{1,2}-?)?\d+(?:-\d+)*)\b`)

// findMRN returns the labelled MRNs in text. RE2 cannot count digits across
// hyphens, so the value is cut here: digit groups are kept while the total
// stays within 10, and the value needs at least 6. "MRN: 4481920-2026" keeps
// 4481920, as the plain 6-10 digit rule always did; 11 digits in one run is
// not an MRN.
func findMRN(text string) [][]int {
	var hits [][]int
	for _, m := range mrnRE.FindAllStringSubmatchIndex(text, -1) {
		val := text[m[2]:m[3]]
		digits, cut := 0, -1
		for i := 0; i <= len(val); i++ {
			if i < len(val) && val[i] != '-' {
				if isDigit(val[i]) {
					digits++
				}
				continue
			}
			if digits > 10 {
				break
			}
			if digits >= 6 {
				cut = i
			}
		}
		if cut >= 0 {
			hits = append(hits, []int{m[0], m[2] + cut})
		}
	}
	return hits
}

// cueStart says where a label may begin. The short labels must start a word
// (stillbirth, newborn, smartphone); some may also follow a camelCase hump
// (memberSsn, homePhone); compounds may be glued to any prefix
// (patientBirthDate, mobile_phone_number).
type cueStart int

const (
	cueWord       cueStart = iota // after a non-letter or the start of the text
	cueWordOrHump                 // or after a lowercase letter, if the label is capitalized
	cueAnywhere
	cueHash // as cueWord, and a "#" must follow ("SS#"), so the bare letters never count
)

type cue struct {
	label string
	start cueStart
}

// dobCues are the labels that make a bare date a date of birth.
var dobCues = []cue{
	{"dob", cueWordOrHump}, {"d.o.b", cueWord}, {"birth", cueWord}, {"born", cueWord}, {"born on", cueWord},
	{"birthdate", cueAnywhere}, {"birth date", cueAnywhere}, {"birth_date", cueAnywhere},
	{"dateofbirth", cueAnywhere}, {"birthday", cueAnywhere},
	{"dobs", cueWordOrHump}, {"birthdates", cueAnywhere}, {"birthdays", cueAnywhere},
	{"birth day", cueAnywhere}, {"birth days", cueAnywhere},
}

// ssnCues are the labels that make nine bare digits an SSN.
var ssnCues = []cue{
	{"ssn", cueWordOrHump}, {"ssns", cueWordOrHump}, {"ssn no", cueWordOrHump}, {"ssn number", cueWordOrHump},
	{"social security", cueWord}, {"social security no", cueWord}, {"social security number", cueWord},
	{"socialsecuritynumber", cueAnywhere}, {"social_security_number", cueAnywhere},
	{"ssnnumber", cueWordOrHump}, {"ssn_number", cueWordOrHump}, {"ss", cueHash}, {"soc sec", cueWord},
}

// phoneCues are the labels that make ten bare digits, or a number spaced
// 3-3-4, a phone number. "call" and "text" are verbs, not labels, but they are
// how a number is given in speech ("call me at 415 555 0173").
var phoneCues = []cue{
	{"phone", cueWordOrHump}, {"phones", cueWordOrHump}, {"tel", cueWordOrHump}, {"telephone", cueWordOrHump},
	{"mobile", cueWordOrHump}, {"cell", cueWordOrHump}, {"fax", cueWordOrHump},
	{"phone no", cueWordOrHump}, {"phone number", cueWordOrHump}, {"mobile number", cueWordOrHump},
	{"cell number", cueWordOrHump}, {"fax number", cueWordOrHump},
	{"phonenumber", cueAnywhere}, {"phone_number", cueAnywhere},
	{"ph", cueWord}, {"cellphone", cueWordOrHump}, {"mobile no", cueWordOrHump}, {"mobileno", cueWordOrHump},
	{"contact number", cueWordOrHump}, {"contactnumber", cueWordOrHump},
	{"call", cueWord}, {"call me", cueWord}, {"call me at", cueWord}, {"call me on", cueWord}, {"call us at", cueWord},
	{"text", cueWord}, {"text me", cueWord}, {"text me at", cueWord}, {"text me on", cueWord},
}

// mbiCues are the labels that make eleven bare characters of the MBI's shape
// an MBI, or let a dashed one be lowercase.
var mbiCues = []cue{
	{"mbi", cueWordOrHump}, {"mbis", cueWordOrHump}, {"mbi no", cueWordOrHump}, {"mbi number", cueWordOrHump},
	{"mbinumber", cueWordOrHump}, {"mbi_number", cueWordOrHump},
	{"medicare", cueWordOrHump}, {"medicare id", cueWordOrHump}, {"medicare no", cueWordOrHump},
	{"medicare number", cueWordOrHump}, {"medicareid", cueWordOrHump}, {"medicare_id", cueWordOrHump},
	{"medicarenumber", cueWordOrHump}, {"medicare_number", cueWordOrHump},
	{"medicare beneficiary id", cueWordOrHump}, {"medicare beneficiary identifier", cueWordOrHump},
}

// The MBI's positions, as regex classes: 1 is a digit 1–9; 2, 5, 8 and 9 a
// letter; 3 and 6 a letter or digit; 4, 7, 10 and 11 a digit. Its letters
// are A–Z less S, L, O, I, B and Z. The recognizers read them under (?i),
// which also folds K onto the Kelvin sign, so mbiValid re-checks each
// position in ASCII.
const (
	mbiLetter = `[AC-HJKMNP-RT-Y]`
	mbiEither = `[0-9AC-HJKMNP-RT-Y]`
	mbiHead   = `[1-9]` + mbiLetter + mbiEither + `\d` // positions 1–4
	mbiMid    = mbiLetter + mbiEither + `\d`           // 5–7
	mbiTail   = mbiLetter + mbiLetter + `\d\d`         // 8–11
	mbiShape  = "1LA9LA9LL99"                          // per position: 1 = 1–9, 9 = 0–9, L = letter, A = either
)

// mbiValid checks a Medicare Beneficiary Identifier position by position, in
// either case, unformatted or dashed after positions 4 and 7 (1EG4-TE5-MK73),
// and rejects one glued to a hyphenated identifier (lot AB-1EG4-TE5-MK73).
func mbiValid(text string, start, end int) bool {
	s := text[start:end]
	if len(s) == 13 && s[4] == '-' && s[8] == '-' {
		s = s[:4] + s[5:8] + s[9:]
	}
	if len(s) != len(mbiShape) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isLower(c) {
			c -= 'a' - 'A'
		}
		letter := isUpper(c) && !strings.ContainsRune("SLOIBZ", rune(c))
		var ok bool
		switch mbiShape[i] {
		case '1':
			ok = c >= '1' && c <= '9'
		case '9':
			ok = isDigit(c)
		case 'L':
			ok = letter
		case 'A':
			ok = letter || isDigit(c)
		}
		if !ok {
			return false
		}
	}
	return notHyphenAdjacent(text, start, end)
}

// mbiDashedValid is mbiValid for the dashed MBI rule, which also needs an MBI
// label before a value that is not all uppercase. Only the regex floor's own
// rule reads it: the type guard stays mbiValid.
func mbiDashedValid(text string, start, end int) bool {
	if !mbiValid(text, start, end) {
		return false
	}
	v := text[start:end]
	return v == strings.ToUpper(v) || labelledBy(text, start, mbiCues)
}

func dobCue(text string, start, _ int) bool { return labelledBy(text, start, dobCues) }

// A clock time right after a date ("10/22/2026 14:30:17", ISO's "T").
var clockAfter = regexp.MustCompile(`^[ T]\d{1,2}:\d{2}`)

// A date range: a connector, then another date on its far side. What
// rangeAfter reads past a date must stay within viewRightReach non-blank bytes
// (window.go); the context checks before a hit, within viewLeftReach.
const rangeJoin = `(?:[\t ]*-{1,2}[\t ]*|[\t ]+(?:to|and|through|thru|until)[\t ]+)`
const anyDate = `\d{1,4}[-/.]\d{1,2}[-/.]\d{2,4}`

var (
	rangeAfter  = regexp.MustCompile(`(?i)^` + rangeJoin + anyDate + `\b`)
	rangeBefore = regexp.MustCompile(`(?i)\b` + anyDate + rangeJoin + `$`)
)

// dobNotEvent accepts an unlabelled MM/DD/YYYY unless it is plainly the date of
// an event: followed by a clock time (a log timestamp), or one end of a range
// ("between 01/01/2026 and 06/30/2026", "01/01/2026-06/30/2026"). A date after
// a birth label is always accepted, and so is the far end of a range whose
// near end has one ("DOBs: 03/14/1985 and 04/02/1990").
func dobNotEvent(text string, start, end int) bool {
	if dobCue(text, start, end) {
		return true
	}
	if clockAfter.MatchString(text[end:]) || rangeAfter.MatchString(text[end:]) {
		return false
	}
	lo := max(start-40, 0)
	if loc := rangeBefore.FindStringIndex(text[lo:start]); loc != nil {
		return dobCue(text, lo+loc[0], start)
	}
	return true
}

// hSpace is horizontal whitespace: tab and the Unicode space separators
// (Zs) people paste in, such as U+00A0, U+2007, U+2009, U+202F and U+3000.
const hSpace = " \t\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000"

// dobPad is what may sit between a birth label and its value: spaces,
// punctuation, the quotes and "=" of a key, and the ">" or "|" closing a tag
// or table cell.
const dobPad = hSpace + ":#.=-\"'(>|"

// labelledBy reports whether one of cues sits immediately before the value
// at start, matched case-insensitively. One "is" or "was" may come between
// them ("SSN is 078051120", "date of birth was 1985-03-14").
func labelledBy(text string, start int, cues []cue) bool {
	if start > 0 && isDigit(text[start-1]) {
		return false
	}
	lo := max(start-40, 0)
	// pad is the run last trimmed off: a cueHash label needs a "#" in it.
	var pad string
	trim := func(s string) string {
		t := strings.TrimRight(s, dobPad)
		pad = s[len(t):]
		return t
	}
	before := trim(text[lo:start])
	// A line break is crossed only after an explicit separator, as for MRN,
	// so a table header ending in a label never claims the next row's value.
	if nl := strings.TrimRight(before, "\r\n"); len(nl) < len(before) {
		nl = strings.TrimRight(nl, hSpace)
		if nl == "" || !strings.ContainsRune("-:=#>", rune(nl[len(nl)-1])) {
			return false
		}
		before = trim(nl)
	}
	// A run of spaces inside a cue ("born  on", "birth\u00a0date") counts as
	// one space.
	before = collapseHSpace(before)
	// FHIR XML carries the value in an attribute: <birthDate value="…"/>.
	if n := len(before) - len(" value"); n >= 0 && strings.EqualFold(before[n:], " value") {
		before = before[:n]
		pad = ""
	}
	for _, verb := range [...]string{" is", " was"} {
		if n := len(before) - len(verb); n >= 0 && strings.EqualFold(before[n:], verb) {
			before = trim(before[:n])
			break
		}
	}
	hash := strings.ContainsRune(pad, '#')
	for _, c := range cues {
		i := len(before) - len(c.label)
		if i < 0 || !strings.EqualFold(before[i:], c.label) {
			continue
		}
		if c.start == cueHash && !hash {
			continue
		}
		if c.start == cueAnywhere || i == 0 || !isAlpha(before[i-1]) {
			return true
		}
		if c.start == cueWordOrHump && isLower(before[i-1]) && isUpper(before[i]) {
			return true
		}
	}
	return false
}

// collapseHSpace replaces each run of horizontal whitespace with one space.
func collapseHSpace(s string) string {
	if !strings.ContainsAny(s, hSpace) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	inSpace := false
	for _, r := range s {
		if strings.ContainsRune(hSpace, r) {
			if !inSpace {
				b.WriteByte(' ')
			}
			inSpace = true
			continue
		}
		inSpace = false
		b.WriteRune(r)
	}
	return b.String()
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
	if !issuable(digits) {
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

// issuable reports whether a Luhn-checked run of 13–19 digits could be a card
// some network issues, judging by its leading digits and length. Luhn alone
// passes one random run in ten, and logs are full of long numbers that are
// not cards: epoch milliseconds (13 digits), microseconds (16) and
// nanoseconds (19), snowflake IDs (18–19), compact timestamps
// (20260922143015) and years in card layout (2023 2024 2025 2026) all start
// 1 or 20. No network issues from a leading 0 (an all-zero placeholder passes
// Luhn), from a leading 1 other than 15-digit UATP, from 2 outside the Mir
// (2200–2204) and Mastercard (2221–2720) ranges, from 31–33, from 7, from 8
// other than UnionPay's 81 and 82, or from 9 other than Troy's 9792: a run of
// port numbers ("8080 8443 9090 3000") passes Luhn too. Fleet cards (7) and
// the other 9xxx national schemes are given up for it.
func issuable(d []int) bool {
	switch d[0] {
	case 0, 7:
		return false
	case 1:
		return len(d) == 15
	case 2:
		p := d[0]*1000 + d[1]*100 + d[2]*10 + d[3]
		return len(d) >= 16 && (p <= 2204 && p >= 2200 || p >= 2221 && p <= 2720)
	case 3:
		return d[1] < 1 || d[1] > 3
	case 8:
		return d[1] == 1 || d[1] == 2
	case 9:
		return d[1] == 7 && d[2] == 9 && d[3] == 2
	}
	return true
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
		if productVersion(text, start) {
			return false
		}
	}
	return true
}

// productVersion reports whether the value at start is the version of a
// User-Agent product token: "Name/" directly before it, the name starting
// with a letter at a space, "(" or the start of the text. Chrome's
// "Chrome/120.0.0.0" has the shape of an IPv4 address; a URL path segment
// ("/api/clients/10.1.2.3") starts after a "/" and is still an address.
func productVersion(text string, start int) bool {
	if start < 2 || text[start-1] != '/' {
		return false
	}
	i := start - 1
	for i > 0 && start-1-i < 40 && (isAlnum(text[i-1]) || text[i-1] == '_' || text[i-1] == '-') {
		i--
	}
	if i == start-1 || !isAlpha(text[i]) {
		return false
	}
	return i == 0 || text[i-1] == ' ' || text[i-1] == '('
}

// ibanValid checks the ISO 13616 mod-97 check digits on the electronic form or
// one grouped by spaces (printed) or hyphens (as Presidio returns it), in any
// case. A registered country must also have
// its registered length. The spaced and lowercase forms are accepted only for
// registered countries, which is what keeps lowercase hex digests out.
func ibanValid(text string, start, end int) bool {
	raw := text[start:end]
	s := strings.ToUpper(ibanSeparators.Replace(raw))
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

var ibanSeparators = strings.NewReplacer(" ", "", "-", "")

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

func isLower(c byte) bool { return c >= 'a' && c <= 'z' }

func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
