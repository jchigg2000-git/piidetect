package piidetect

import (
	"unicode"
	"unicode/utf8"
)

// Values arrive percent-encoded in a URL query or a form body
// (jane.doe%40example.org, 4111+1111+1111+1111, DOB%3A%203%2F14%2F1985) and
// with Unicode look-alikes of ASCII punctuation in pasted documents
// (219–09–9999 with en dashes, a card number's non-breaking spaces). The
// recognizers also read the text normalized, so one pass covers every type, its
// labels included, and the spans are mapped back onto the text as given.

// normalizedView returns text as the recognizers should also read it: with
// every valid %XX escape replaced by its byte and every '+' by a space, as a
// query string or form body is decoded, and then with the look-alikes of
// ASCII punctuation folded onto it, which are what a document pasted from a
// word processor or PDF carries: the Unicode dashes that stand for a hyphen
// (U+2010–U+2013, U+2212; not the em dash, which is a sentence's own
// punctuation), every Unicode space (non-breaking, thin, ideographic) for a
// space, and the fullwidth forms U+FF01–U+FF5E (３１４, ＭＲＮ：, ＠) for their
// ASCII originals.
//
// orig[i] is the offset in text at which view byte i begins (orig[len(view)] is
// len(text)), so a span found in the view can be mapped back. ok is false, and
// nothing is allocated, unless text holds an escape, a '+' between two letters
// or digits (the shape of a form-encoded space), or a character to fold; that
// keeps the second pass off ordinary text.
func normalizedView(text string) (view string, orig []int, ok bool) {
	s, o, decoded := percentDecoded(text)
	if !decoded {
		s = text
	}
	if !hasFoldable(s) {
		return s, o, decoded
	}
	at := func(i int) int {
		if o == nil {
			return i
		}
		return o[i]
	}
	b := make([]byte, 0, len(s))
	orig = make([]int, 0, len(s)+1)
	for i := 0; i < len(s); {
		f, n, ok := fold(s, i)
		switch {
		case !ok:
			for k := 0; k < n; k++ {
				b = append(b, s[i+k])
				orig = append(orig, at(i+k))
			}
		case f != dropped:
			b = append(b, f)
			orig = append(orig, at(i))
		}
		i += n
	}
	return string(b), append(orig, at(len(s))), true
}

// hasFoldable reports whether s holds a character that fold maps.
func hasFoldable(s string) bool {
	for i := 0; i < len(s); {
		if s[i] < utf8.RuneSelf {
			i++
			continue
		}
		_, n, ok := fold(s, i)
		if ok {
			return true
		}
		i += n
	}
	return false
}

// dropped is what fold maps an invisible character to: it gets no byte in the
// view, so a span read across it still covers it in the text as given.
const dropped byte = 0

// fold maps the non-ASCII character at s[i:], n bytes long, to the ASCII one
// it stands for, or to dropped. ok is false for ASCII and for a character that
// stands for nothing else.
func fold(s string, i int) (f byte, n int, ok bool) {
	if s[i] < utf8.RuneSelf {
		return 0, 1, false
	}
	r, n := utf8.DecodeRuneInString(s[i:])
	switch {
	case r >= 0xFF01 && r <= 0xFF5E: // fullwidth forms, including －
		return byte(r - 0xFEE0), n, true
	case r >= 0x2010 && r <= 0x2013, r == 0x2212, r == 0xFE58, r == 0xFE63:
		return '-', n, true
	// The katakana prolonged sound mark and the hyphen bullet are a hyphen
	// only inside a number (219ー09ー9999); in words they are themselves.
	case r == 0x30FC, r == 0x2043:
		return '-', n, unicode.IsDigit(lastRune(s[:i])) && unicode.IsDigit(firstRune(s[i+n:]))
	case r == 0xFE6B: // small commercial at
		return '@', n, true
	// Soft hyphen, zero-width space, non-joiner and joiner, word joiner and
	// byte-order mark: invisible, and inside a value they hide it.
	case r == 0x00AD, r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF:
		return dropped, n, true
	case unicode.Is(unicode.Zs, r):
		return ' ', n, true
	}
	if d, ok := digitValue(r); ok {
		return '0' + d, n, true
	}
	return 0, n, false
}

// digitValue is the value of a decimal digit in any script (Arabic-Indic ٣,
// Persian ۳, Devanagari ३). Unicode encodes each script's digits as one run
// from 0 to 9, and unicode.Nd lists them in whole runs.
func digitValue(r rune) (byte, bool) {
	if !unicode.IsDigit(r) {
		return 0, false
	}
	for _, rg := range unicode.Nd.R16 {
		if r >= rune(rg.Lo) && r <= rune(rg.Hi) {
			return byte((r - rune(rg.Lo)) % 10), true
		}
	}
	for _, rg := range unicode.Nd.R32 {
		if r >= rune(rg.Lo) && r <= rune(rg.Hi) {
			return byte((r - rune(rg.Lo)) % 10), true
		}
	}
	return 0, false
}

func lastRune(s string) rune {
	r, _ := utf8.DecodeLastRuneInString(s)
	return r
}

func firstRune(s string) rune {
	r, _ := utf8.DecodeRuneInString(s)
	return r
}

// percentDecoded is text with each valid %XX escape replaced by its byte and
// each '+' by a space, plus orig as for normalizedView. ok is false, and nothing
// is allocated, when text has neither.
func percentDecoded(text string) (dec string, orig []int, ok bool) {
	for i := 0; i < len(text) && !ok; i++ {
		switch text[i] {
		case '%':
			ok = isEscape(text, i)
		case '+':
			ok = i > 0 && i+1 < len(text) && isAlnum(text[i-1]) && isAlnum(text[i+1])
		}
	}
	if !ok {
		return "", nil, false
	}
	b := make([]byte, 0, len(text))
	orig = make([]int, 0, len(text)+1)
	for i := 0; i < len(text); {
		orig = append(orig, i)
		switch {
		case isEscape(text, i):
			b = append(b, unhex(text[i+1])<<4|unhex(text[i+2]))
			i += 3
		case text[i] == '+':
			b = append(b, ' ')
			i++
		default:
			b = append(b, text[i])
			i++
		}
	}
	return string(b), append(orig, len(text)), true
}

// isEscape reports whether text[i:] starts with a %XX escape.
func isEscape(text string, i int) bool {
	return text[i] == '%' && i+2 < len(text) && isHex(text[i+1]) && isHex(text[i+2])
}

func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case isDigit(c):
		return c - '0'
	case c >= 'a':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}
