package piidetect

import (
	"net/netip"
	"strings"
)

// IPv6 is found by scanning rather than by a regular expression: the candidate
// is a run of hex digits, colons and dots, and what separates an address from
// a MAC, a clock time, a C++ scope (std::string) or a Haskell signature is
// context and structure that a pattern cannot state. The scan is linear.

// maxIPv6Run bounds a candidate run. The longest address in text form is 45
// bytes (an IPv4-mapped one in full); the slack covers trailing punctuation.
// A longer run is a hash or a blob, and bounding it keeps the scan from
// looking at every start inside one.
const maxIPv6Run = 64

func isV6Char(c byte) bool { return isHex(c) || c == ':' || c == '.' }

// findIPv6 returns the [start, end) of each IPv6 address in text.
func findIPv6(text string) [][]int {
	var hits [][]int
	for i := 0; i < len(text); {
		if !isV6Char(text[i]) {
			i++
			continue
		}
		j, colons := i, 0
		for j < len(text) && isV6Char(text[j]) {
			if text[j] == ':' {
				colons++
			}
			j++
		}
		if colons >= 2 && j-i <= maxIPv6Run && (j == len(text) || !isWord(text[j])) {
			if s, e, ok := v6Value(text, i, j); ok {
				hits = append(hits, []int{s, e})
			}
		}
		i = j
	}
	return hits
}

// v6Value finds the address in the run text[i:j]: the run itself, or the run
// less a leading label colon ("ip:2001:db8::1"), or less the label glued to
// that colon ("IPv6:2001:db8::1"), and less trailing sentence punctuation.
func v6Value(text string, i, j int) (start, end int, ok bool) {
	start, end = i, j
	switch {
	case text[start] == ':' && !strings.HasPrefix(text[start:end], "::"):
		start++ // a label's colon: "ip:2001:db8::1"
	case start > 0 && isWord(text[start-1]):
		// Glued to a word, which is only an address when the word is the
		// SMTP-style label of one ("IPv6:2001:db8::1": the label's 6 is hex).
		k := strings.IndexByte(text[start:end], ':')
		if k < 0 || strings.HasPrefix(text[start+k:end], "::") {
			return 0, 0, false
		}
		w := start
		for w > 0 && isWord(text[w-1]) {
			w--
		}
		if !ipv6Labels[strings.ToLower(text[w:start+k])] {
			return 0, 0, false
		}
		start += k + 1
	}
	for end > start && text[end-1] == '.' {
		end--
	}
	if end > start && text[end-1] == ':' && !strings.HasSuffix(text[start:end], "::") {
		end--
	}
	if start >= end || !ipv6Plausible(text[start:end]) {
		return 0, 0, false
	}
	return start, end, true
}

// ipv6Labels end in a hex digit, so a label glued to its address by a colon
// reads as part of the run.
var ipv6Labels = map[string]bool{"ipv6": true, "ip6": true, "inet6": true}

func isWord(c byte) bool { return isAlnum(c) || c == '_' }

// ipv6Plausible reports whether s is an IPv6 address worth claiming: it
// parses, it has at least three groups (an embedded IPv4 counts as two), so
// that "::1" and the "a::b" of code do not qualify, and, written without "::",
// it is not eight groups of two digits, which is a MAC-64 or a WWN.
func ipv6Plausible(s string) bool {
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is6() || addr.Zone() != "" {
		return false
	}
	groups, wide := 0, false
	for _, g := range strings.Split(s, ":") {
		switch {
		case g == "":
		case strings.Contains(g, "."):
			groups += 2
			wide = true
		default:
			groups++
			wide = wide || len(g) != 2
		}
	}
	if groups < 3 {
		return false
	}
	return strings.Contains(s, "::") || wide
}
