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
		r, n := utf8.DecodeRuneInString(s[i:])
		if f, ok := fold(r); ok && n > 1 {
			b = append(b, f)
			orig = append(orig, at(i))
			i += n
			continue
		}
		for k := 0; k < n; k++ {
			b = append(b, s[i+k])
			orig = append(orig, at(i+k))
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
		r, n := utf8.DecodeRuneInString(s[i:])
		if _, ok := fold(r); ok {
			return true
		}
		i += n
	}
	return false
}

// fold maps a non-ASCII character to the ASCII one it stands for.
func fold(r rune) (byte, bool) {
	switch {
	case r >= 0xFF01 && r <= 0xFF5E: // fullwidth forms, including －
		return byte(r - 0xFEE0), true
	case r >= 0x2010 && r <= 0x2013, r == 0x2212, r == 0xFE58, r == 0xFE63:
		return '-', true
	case unicode.Is(unicode.Zs, r):
		return ' ', true
	}
	return 0, false
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
