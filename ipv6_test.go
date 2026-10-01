package piidetect

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRedactIPv6(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"from 2001:db8:85a3::8a2e:370:7334 to", "from [IP] to"},
		{"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "[IP]"},
		{"([IPv6:2606:4700:4700::1111])", "([IPv6:[IP]])"},
		{"ip:2001:db8::1:2, next", "ip:[IP], next"},
		{"[2001:db8::1:2]:8080", "[[IP]]:8080"},
		{"http://[2001:db8::1:2]/x", "http://[[IP]]/x"},
		{"ends here 2001:db8::1:2.", "ends here [IP]."},
		{"prefix 2001:db8:abcd:12::/64 routed", "prefix [IP]/64 routed"},
		{"::ffff:192.168.1.100 mapped", "[IP] mapped"},
		{"zone fe80::1ff:fe23:4567:890a%eth0", "zone [IP]%eth0"},
		{"q=ip%3D2001%3Adb8%3A85a3%3A%3A8a2e%3A370%3A7334&x=1", "q=ip%3D[IP]&x=1"},
		// Not addresses: scopes, MACs and WWNs, times, slices, glued words.
		{"std::string Foo::Bar dead::beef a::b x[::2] 1::2::3", "std::string Foo::Bar dead::beef a::b x[::2] 1::2::3"},
		{"::1 fe80::1 ::", "::1 fe80::1 ::"},
		{"00:1A:2B:3C:4D:5E 00:1a:2b:ff:fe:3c:4d:5e 50:06:01:60:3b:a0:12:34", "00:1A:2B:3C:4D:5E 00:1a:2b:ff:fe:3c:4d:5e 50:06:01:60:3b:a0:12:34"},
		{"12:30:45.123 and 1:2:3 and 10:20:30:40:50:60:70:80", "12:30:45.123 and 1:2:3 and 10:20:30:40:50:60:70:80"},
		{"2001:db8::1:2g g2001:db8::1:2 2001:db8::1:2:3:4:5:6:7", "2001:db8::1:2g g2001:db8::1:2 2001:db8::1:2:3:4:5:6:7"},
	} {
		if got, _ := New().Redact(context.Background(), c.in); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The scan reads each run of hex digits, colons and dots once, and gives up on
// a run too long to be an address, so hostile input costs time in proportion
// to its size.
func TestIPv6ScanIsLinear(t *testing.T) {
	for name, s := range map[string]string{
		"hex run":    strings.Repeat("a", 1<<20),
		"colon run":  strings.Repeat(":", 1<<20),
		"pairs":      strings.Repeat("a:", 1<<19),
		"groups":     strings.Repeat("2001:db8::1:2 ", 1<<16),
		"near limit": strings.Repeat("2001:db8:85a3::8a2e:370:7334:1:2:3:4:5:6:7:8:9:", 1<<15),
	} {
		start := time.Now()
		findIPv6(s)
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("%s: %d bytes took %v", name, len(s), d)
		}
	}
}
