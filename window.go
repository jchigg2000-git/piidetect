package piidetect

import (
	"regexp"
	"regexp/syntax"
	"unicode"
	"unicode/utf8"
)

// The normalized view differs from the text as given only around the bytes a
// decode or fold changed, and one %20 or non-breaking space in a megabyte must
// not cost a second read of the megabyte. detectRaw therefore re-reads only
// windows of the view around the changed bytes, and the result is exactly the
// one a read of the whole view gives (TestWindowedViewMatchesFullRead). The
// argument has three parts.
//
// Segments. A recognizer's cut bytes are the ASCII bytes no match of it can
// hold: for a regex, every ASCII byte none of its literals or classes admits
// (a space for EMAIL, a letter for SSN, a comma for MRN), derived from the
// regex itself by regexCuts; for a hand-written finder, the set its table entry
// declares. A regex that can match the empty string has none. No hit holds a
// cut byte, so the hits a recognizer reports between two cut bytes depend on
// those bytes alone: a leftmost-first search that reaches a cut byte resumes
// past it whatever it found before, no hit starts or ends on a piece's edge
// where ^ and $ would read differently, and \b at the first byte inside reads
// the cut byte kept before it. A window is a union of whole segments, cut byte
// to cut byte, so reading it finds exactly the whole read's hits inside it,
// however long they are: an address of 254 bytes, a grouped IBAN, a pack rule
// with no bound. A margin of the longest match would not do: hits that abut
// (a run of spaced single digits read as cards) chain the search from one to
// the next, and a change shifts every match after it until a cut byte.
// Validators and guards still judge each hit in the whole view.
//
// Context. Validators, cue labels and type guards read past a hit. Before it:
// at most 80 bytes (labelledBy reads 40; dobNotEvent looks 40 back for a range
// and asks labelledBy about its start; productVersion 42, hyphenLabel 9). That
// is viewLeftReach. After it: a few bytes (hyphen adjacency, a digit run, an
// OID's next field, a clock time), a date range's connector and far date
// (rangeAfter: under 20 non-blank bytes, its blanks unbounded), and an
// address's ':' path, read up to the next emailPathEnd byte. A changed run at
// [a, b) therefore concerns every hit that starts before b+viewLeftReach and
// whose read after it reaches a: an end with fewer than viewRightReach
// non-blank bytes before a, or no emailPathEnd byte between it and a.
//
// Everything else. A hit of the whole read outside every window lies in a
// segment with no changed byte, between cut bytes that are not changed, with
// none in its context either. The text as given holds the same bytes there,
// one for one, so the read as given found the same hit, judged it the same
// way, and placed it at the same offsets: a needed literal it holds is held as
// given too, a cue it was read after stands there as given, and a JSON escape
// pastEscape would step over is itself a changed byte. That hit merges into
// its twin, and the chain's guard rules on the twin as the view's did on the
// hit. A hit that holds or reads a changed byte, a value the read as given saw
// only in part among them, lies in a window and is found there in full.

// viewLeftReach is how many bytes before a hit validation reads, 80, with
// room for a validator that reads a little further; see above.
const viewLeftReach = 96

// viewRightReach is how many non-blank bytes after a hit validation reads,
// other than an address's path: under 20 for a date range; see above.
const viewRightReach = 32

// cutSet marks the ASCII bytes no hit of a recognizer holds.
type cutSet [utf8.RuneSelf]bool

// cutsWhere is the cut set of the ASCII bytes cut reports.
func cutsWhere(cut func(c byte) bool) *cutSet {
	var s cutSet
	for c := range s {
		s[c] = cut(byte(c))
	}
	return &s
}

// regexCuts is the cut set of re: every ASCII byte no match of it can hold.
// It is nil, so the whole view is read, when re can match the empty string,
// holds an operator this does not know, or admits every ASCII byte.
func regexCuts(re *regexp.Regexp) *cutSet {
	if re == nil {
		return nil
	}
	ast, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil || minWidth(ast) == 0 {
		return nil
	}
	var held cutSet
	if !holds(ast, &held) {
		return nil
	}
	var cuts cutSet
	some := false
	for c := range cuts {
		cuts[c] = !held[c]
		some = some || cuts[c]
	}
	if !some {
		return nil
	}
	return &cuts
}

// holds marks in held every ASCII byte a match of re may hold. It reports
// false for an operator it does not know.
func holds(re *syntax.Regexp, held *cutSet) bool {
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			holdRune(r, held)
			if re.Flags&syntax.FoldCase != 0 {
				for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
					holdRune(f, held)
				}
			}
		}
		return true
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for c := max(re.Rune[i], 0); c <= re.Rune[i+1] && c < utf8.RuneSelf; c++ {
				held[c] = true
			}
		}
		return true
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		for c := range held {
			held[c] = re.Op == syntax.OpAnyChar || c != '\n' || held[c]
		}
		return true
	case syntax.OpCapture, syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat,
		syntax.OpConcat, syntax.OpAlternate:
		for _, sub := range re.Sub {
			if !holds(sub, held) {
				return false
			}
		}
		return true
	}
	return false
}

func holdRune(r rune, held *cutSet) {
	if r >= 0 && r < utf8.RuneSelf {
		held[r] = true
	}
}

// minWidth is the fewest bytes a match of re holds; only zero matters here.
func minWidth(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		return len(re.Rune)
	case syntax.OpCharClass, syntax.OpAnyCharNotNL, syntax.OpAnyChar, syntax.OpNoMatch:
		return 1
	case syntax.OpCapture, syntax.OpPlus:
		return minWidth(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min * minWidth(re.Sub[0])
	case syntax.OpConcat:
		n := 0
		for _, sub := range re.Sub {
			n += minWidth(sub)
		}
		return n
	case syntax.OpAlternate:
		n := -1
		for _, sub := range re.Sub {
			if w := minWidth(sub); n < 0 || w < n {
				n = w
			}
		}
		return max(n, 0)
	}
	return 0
}

// changedRuns returns the runs [a, b) of view bytes that are not the text's
// own bytes in place: decoded, folded, or next to a byte the view dropped or
// to a jump in orig.
func changedRuns(text, view string, orig []int) [][2]int {
	gap := func(k int) bool {
		if k == 0 {
			return orig[0] != 0
		}
		return orig[k] != orig[k-1]+1
	}
	var runs [][2]int
	for i := 0; i < len(view); i++ {
		if view[i] == text[orig[i]] && !gap(i) && !gap(i+1) {
			continue
		}
		if n := len(runs); n > 0 && runs[n-1][1] == i {
			runs[n-1][1] = i + 1
		} else {
			runs = append(runs, [2]int{i, i + 1})
		}
	}
	return runs
}

// viewReach returns, for each changed run [a, b), the span [lo, hi) of view
// positions a hit that concerns the run holds one of: it starts before hi =
// b+viewLeftReach and ends after lo, the furthest end left of a whose read
// after it still reaches a. lo and hi rise run by run. A walk left from a stops
// at the previous run's a: a read that reaches a from further left passes that
// run first, so its hit is that run's concern already.
func viewReach(view string, runs [][2]int) [][2]int {
	reach := make([][2]int, len(runs))
	floor := 0
	for i, r := range runs {
		a, b := r[0], r[1]
		lo, nonBlank := a, 0
		for lo > floor && nonBlank < viewRightReach {
			lo--
			if c := view[lo]; c != ' ' && c != '\t' {
				nonBlank++
			}
		}
		// emailValid reads an address's ':' path from end+1 up to the next
		// emailPathEnd byte d, so an end of d-1 or later reaches a.
		path := floor
		for k := a - 1; k > floor; k-- {
			if isEmailPathEnd(view[k]) {
				path = max(k-1, floor)
				break
			}
		}
		reach[i] = [2]int{min(lo, path), min(b+viewLeftReach, len(view))}
		floor = a
	}
	return reach
}

// windows returns the pieces [from, to) of view a recognizer with cut set cuts
// reads: for each [lo, hi) of reach, every segment holding a position in it,
// from the cut byte before to the cut byte after (each kept, so the edges read
// as in the whole view) or the end of the view. Pieces that meet are joined.
// With no cut set it is the whole view.
func windows(view string, reach [][2]int, cuts *cutSet) [][2]int {
	n := len(view)
	if cuts == nil {
		return [][2]int{{0, n}}
	}
	isCut := func(k int) bool { return view[k] < utf8.RuneSelf && cuts[view[k]] }
	var out [][2]int
	end := -1 // the last piece's closing cut byte, or n
	for _, r := range reach {
		lo, hi := r[0], r[1]
		if len(out) == 0 || lo > end {
			x := lo
			for x >= 0 && !isCut(x) {
				x--
			}
			// x stops at the last piece's closing cut byte at the latest.
			if len(out) == 0 || x > end {
				out = append(out, [2]int{max(x, 0), max(x, 0)})
				end = x
			}
		}
		if y := hi - 1; y > end {
			for y < n && !isCut(y) {
				y++
			}
			end = y
			out[len(out)-1][1] = min(y+1, n)
		}
	}
	return out
}
