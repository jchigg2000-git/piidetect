package piidetect

// Values in a URL query or a form body arrive percent-encoded
// (jane.doe%40example.org, 4111+1111+1111+1111, DOB%3A%203%2F14%2F1985). The
// recognizers read the decoded text, so one pass covers every type, its
// labels included, and the spans are mapped back onto the text as given.

// decodedView returns text with every valid %XX escape replaced by its byte
// and every '+' by a space, as a query string or form body is decoded, and
// orig, where orig[i] is the offset in text at which decoded byte i begins
// (orig[len(dec)] is len(text)). ok is false, and nothing is allocated, unless
// text holds an escape or a '+' between two letters or digits (the shape of a
// form-encoded space); that is what keeps the second pass off ordinary text.
func decodedView(text string) (dec string, orig []int, ok bool) {
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
