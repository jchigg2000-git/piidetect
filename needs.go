package piidetect

import (
	"regexp/syntax"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A recognizer is skipped on a text that cannot hold a match: an EMAIL needs an
// "@", the MRN rule its label, an unlabelled-shape SSN, PHONE or DOB one of its
// cue words. Most text holds none of these, and the labelled-DOB regex alone
// was over a third of the floor's time on clean text.
//
// The literals are never listed by hand. They are derived from the regex
// itself (requiredLits) and from the cue table labelledBy reads (cueNeeds), so
// a cue or alternative added to either is covered the moment it is added.
// Both derivations are conservative: when they cannot prove a literal is
// required, they require nothing and the recognizer always runs.
//
// Every literal is compared against the text lowered in ASCII only
// (asciiLower), so a literal is ASCII-lowercase and otherwise verbatim.

// needs is a conjunction of disjunctions: the text must hold, for each set, at
// least one of its literals. Empty means the recognizer always runs.
type needs [][]string

func (n needs) metBy(lower string) bool {
	for _, anyOf := range n {
		if !slices.ContainsFunc(anyOf, func(lit string) bool { return strings.Contains(lower, lit) }) {
			return false
		}
	}
	return true
}

// withNeeds returns rec with its needs derived from its regex and cues, and,
// for a regex recognizer, its cut bytes (regexCuts).
func (rec recognizer) withNeeds() recognizer {
	rec.needs = nil
	if rec.find == nil {
		rec.cuts = regexCuts(rec.re)
	}
	if lits := cueNeeds(rec.cues); lits != nil {
		rec.needs = append(rec.needs, lits)
	}
	src := rec.re
	if rec.find != nil {
		src = rec.findRE
	}
	if src != nil {
		if lits := regexNeeds(src.String()); lits != nil {
			rec.needs = append(rec.needs, lits)
		}
	}
	return rec
}

// asciiLower is s with A–Z lowered and every other byte kept, so a match's
// bytes lower one for one and a literal found in a match is found here.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// cueNeeds is the literals one of which a text must hold for labelledBy to
// find any of cues in it. labelledBy compares a label with strings.EqualFold
// on a slice of the same byte length, so an ASCII label only ever matches
// ASCII bytes, and the only rewrite it applies first is a run of horizontal
// space read as one space; every space-free piece of a label therefore stands
// verbatim, up to ASCII case, in the text. Each cue contributes its longest
// piece: one that holds a literal another cue already contributes ("ssn" for
// "ssn number"), else its longest. A non-ASCII label, or one with no piece,
// makes the set unknown: nil.
func cueNeeds(cues []cue) []string {
	if len(cues) == 0 {
		return nil
	}
	pieces := make([][]string, len(cues))
	var lits []string
	for i, c := range cues {
		if !isASCII(c.label) {
			return nil
		}
		pieces[i] = strings.FieldsFunc(asciiLower(c.label), func(r rune) bool { return strings.ContainsRune(hSpace, r) })
		switch len(pieces[i]) {
		case 0:
			return nil
		case 1:
			lits = append(lits, pieces[i][0])
		}
	}
	single := slices.Clone(lits)
	for _, ps := range pieces {
		if len(ps) < 2 || slices.ContainsFunc(ps, func(p string) bool {
			return slices.ContainsFunc(single, func(l string) bool { return strings.Contains(p, l) })
		}) {
			continue
		}
		lits = append(lits, slices.MaxFunc(ps, func(a, b string) int { return len(a) - len(b) }))
	}
	return minimalLits(lits)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// minimalLits sorts and dedupes lits and drops each literal that holds another
// (a text holding "telephone" holds "tel"), which leaves the set's meaning as
// "any of" unchanged.
func minimalLits(lits []string) []string {
	slices.Sort(lits)
	lits = slices.Compact(lits)
	var out []string
	for _, l := range lits {
		if !slices.ContainsFunc(lits, func(o string) bool { return o != l && strings.Contains(l, o) }) {
			out = append(out, l)
		}
	}
	return out
}

// regexNeeds is a set of literals one of which every match of expr holds, or
// nil when none can be proved. It parses expr as regexp.Compile does.
func regexNeeds(expr string) []string {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil
	}
	lits := analyze(re).required()
	if lits == nil {
		return nil
	}
	return minimalLits(lits)
}

// maxLits bounds a literal set, so cross products stay small.
const maxLits = 64

// litInfo describes what a regex node matches, each string lowered as
// asciiLower would. When exact is non-nil the node matches only those strings.
// Otherwise req, if non-nil, holds strings one of which every match contains,
// and prefix, if non-nil, strings one of which every match starts with.
type litInfo struct {
	exact  []string
	req    []string
	prefix []string
}

var unknown = litInfo{}

// proves is s, or nil when s holds nothing to look for: it is empty or holds
// "", which every text contains.
func proves(s []string) []string {
	if len(s) == 0 || slices.Contains(s, "") {
		return nil
	}
	return s
}

// starts is the strings one of which every match starts with, or nil.
func (in litInfo) starts() []string {
	if in.exact != nil {
		return in.exact
	}
	return in.prefix
}

// required is the best set the node proves one of which every match holds.
func (in litInfo) required() []string {
	if in.exact != nil {
		return proves(in.exact)
	}
	best := proves(in.req)
	if p := proves(in.prefix); better(p, best) {
		best = p
	}
	return best
}

// better reports whether literal set a filters more than b: longer shortest
// literal, then fewer literals. A nil set is never better.
func better(a, b []string) bool {
	if a == nil {
		return false
	}
	if b == nil {
		return true
	}
	ma, mb := minLen(a), minLen(b)
	return ma > mb || ma == mb && len(a) < len(b)
}

func minLen(s []string) int {
	m := -1
	for _, l := range s {
		if m < 0 || len(l) < m {
			m = len(l)
		}
	}
	return m
}

// analyze is what re's matches must hold. Every rule errs towards unknown.
func analyze(re *syntax.Regexp) litInfo {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return litInfo{exact: []string{""}}
	case syntax.OpLiteral:
		set := []string{""}
		for _, r := range re.Rune {
			alts := runeForms(r, re.Flags&syntax.FoldCase != 0)
			if alts == nil {
				return unknown
			}
			if set = cross(set, alts); set == nil {
				return unknown
			}
		}
		return litInfo{exact: set}
	case syntax.OpCharClass:
		// Small classes only: [- ], [-/.]. A digit or letter range proves
		// nothing worth checking.
		var set []string
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if hi-lo >= 4 {
				return unknown
			}
			for r := lo; r <= hi; r++ {
				alts := runeForms(r, false)
				if alts == nil {
					return unknown
				}
				set = append(set, alts...)
			}
			if len(set) > 4 {
				return unknown
			}
		}
		if len(set) == 0 {
			return unknown
		}
		slices.Sort(set)
		return litInfo{exact: slices.Compact(set)}
	case syntax.OpCapture:
		return analyze(re.Sub[0])
	case syntax.OpQuest:
		sub := analyze(re.Sub[0])
		if sub.exact == nil || len(sub.exact) >= maxLits {
			return unknown
		}
		return litInfo{exact: append(slices.Clone(sub.exact), "")}
	case syntax.OpPlus, syntax.OpRepeat:
		if re.Op == syntax.OpRepeat && re.Min < 1 {
			return unknown
		}
		sub := analyze(re.Sub[0])
		return litInfo{req: sub.required(), prefix: sub.starts()}
	case syntax.OpAlternate:
		infos := make([]litInfo, len(re.Sub))
		var exact []string
		allExact := true
		for i, sub := range re.Sub {
			infos[i] = analyze(sub)
			if infos[i].exact == nil {
				allExact = false
			}
			exact = append(exact, infos[i].exact...)
		}
		if allExact && len(exact) <= maxLits {
			slices.Sort(exact)
			return litInfo{exact: slices.Compact(exact)}
		}
		// A set holds for the alternation only if every branch proves one: a
		// branch that proves none may be the one that matched.
		var req, prefix []string
		reqOK, prefixOK := true, true
		for _, in := range infos {
			if r := in.required(); r != nil {
				req = append(req, r...)
			} else {
				reqOK = false
			}
			if p := in.starts(); p != nil {
				prefix = append(prefix, p...)
			} else {
				prefixOK = false
			}
		}
		var out litInfo
		if reqOK && len(req) <= maxLits {
			slices.Sort(req)
			out.req = slices.Compact(req)
		}
		if prefixOK && len(prefix) <= maxLits {
			slices.Sort(prefix)
			out.prefix = slices.Compact(prefix)
		}
		return out
	case syntax.OpConcat:
		// Adjacent exact children run together as a cross product, and a run
		// joins the prefix of the child after it; the best of those runs and
		// of the other children's sets is required. The match starts with the
		// first run, joined if it can be.
		var best, prefix []string
		consider := func(s []string) {
			if s = proves(s); better(s, best) {
				best = s
			}
		}
		run, allExact, prefixSet := []string{""}, true, false
		for _, sub := range re.Sub {
			in := analyze(sub)
			if in.exact != nil {
				if next := cross(run, in.exact); next != nil {
					run = next
					continue
				}
				if !prefixSet {
					prefix, prefixSet = run, true
				}
				allExact = false
				consider(run)
				run = in.exact
				continue
			}
			allExact = false
			joined := run
			if p := in.prefix; p != nil {
				if j := cross(run, p); j != nil {
					joined = j
				}
			}
			if !prefixSet {
				prefix, prefixSet = joined, true
			}
			consider(joined)
			consider(in.required())
			run = []string{""}
		}
		if allExact {
			return litInfo{exact: run}
		}
		consider(run)
		return litInfo{req: best, prefix: prefix}
	}
	return unknown
}

// runeForms is every string rune r can match as, lowered as asciiLower would:
// r itself, or its whole simple case-folding orbit when fold is set. nil when
// r is utf8.RuneError, which RE2 also matches against an invalid byte.
func runeForms(r rune, fold bool) []string {
	if r == utf8.RuneError {
		return nil
	}
	lower := func(r rune) string {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		return string(r)
	}
	forms := []string{lower(r)}
	if fold {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f == utf8.RuneError {
				return nil
			}
			forms = append(forms, lower(f))
		}
	}
	slices.Sort(forms)
	return slices.Compact(forms)
}

// cross is every a followed by every b, or nil when that exceeds maxLits.
func cross(a, b []string) []string {
	if len(a)*len(b) > maxLits {
		return nil
	}
	out := make([]string, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			out = append(out, x+y)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
