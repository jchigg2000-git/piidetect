package piidetect

import (
	"context"
	"encoding/json"
	"testing"
)

// Offsets are the contract: a span found in the decoded text must land on the
// escapes of the text as given, no more and no less, or Mask would cut the
// wrong bytes.
func TestDecodedViewMapsOffsets(t *testing.T) {
	text := "a%40b+c%C3%BCd"
	dec, orig, ok := normalizedView(text)
	if !ok || dec != "a@b cüd" {
		t.Fatalf("normalizedView(%q) = %q, %v", text, dec, ok)
	}
	if len(orig) != len(dec)+1 || orig[len(dec)] != len(text) {
		t.Fatalf("orig = %v, want one entry per decoded byte plus the text length", orig)
	}
	// a  %40  b  +  c  %C3  %BC  d
	for i, want := range []int{0, 1, 4, 5, 6, 7, 10, 13, 14} {
		if orig[i] != want {
			t.Errorf("orig[%d] = %d, want %d (orig %v)", i, orig[i], want, orig)
		}
	}
}

// Ordinary text must not pay for a second pass: no escape and no form-encoded
// space means no view and no allocation, and a malformed escape is not one.
func TestDecodedViewOnlyForEncodedText(t *testing.T) {
	for _, plain := range []string{
		"", "Order 12 shipped", "100%", "50%4", "%zz and %4", "C++ and +1 415 555 0173", "1 +", "+x",
	} {
		if _, _, ok := normalizedView(plain); ok {
			t.Errorf("normalizedView(%q) = ok, want no view", plain)
		}
	}
	if n := testing.AllocsPerRun(10, func() { normalizedView("Order 12 shipped, 100%") }); n != 0 {
		t.Errorf("plain text allocated %.0f times in normalizedView", n)
	}
	for _, enc := range []string{"a%40b", "a+b", "x=%2B1"} {
		if _, _, ok := normalizedView(enc); !ok {
			t.Errorf("normalizedView(%q) = no view, want one", enc)
		}
	}
}

// The values of a query string or form body, masked whole and exactly, through
// the chain: its type guards read the text as given, so a span found in the
// decoded text must not be judged there a second time.
func TestRedactPercentEncodedValues(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"mailto:jane.doe%40example.org?subject=hi", "mailto:[EMAIL]?subject=hi"},
		{"card=4111+1111+1111+1111&x=1", "card=[CREDIT_CARD]&x=1"},
		{"card=4111%201111%201111%201111&x=1", "card=[CREDIT_CARD]&x=1"},
		{"ssn=219%2009%209999&x=1", "ssn=[SSN]&x=1"},
		{"q=DOB%3A%203%2F14%2F1985+ok", "q=DOB%3A%20[DOB]+ok"},
		{"q=Patient+MRN%3A%204481920+seen", "q=Patient+[MRN]+seen"},
		{"tel=%2B14155550173", "tel=[PHONE]"},
		{"ip=192%2E168%2E1%2E100", "ip=[IP]"},
		{"iban=DE89%203704%200044%200532%200130%2000", "iban=[IBAN]"},
		// Decoded, it is still a hyphenated identifier, and still not an SSN.
		{"ref=ORD%2D123%2D45%2D6789", "ref=ORD%2D123%2D45%2D6789"},
		{"n=1+1&m=a+b&c=C%2B%2B", "n=1+1&m=a+b&c=C%2B%2B"},
	} {
		if got, _ := New().Redact(context.Background(), c.in); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// An allow-list term is ruled on as it reads, so it covers its encoded form.
func TestAllowListMatchesEncodedForm(t *testing.T) {
	text := "mailto:support%40example.com and mailto:jane%40example.com"
	c := New()
	c.SetPatternPack([]PatternRule{{ID: "ours", Type: "EMAIL", Kind: "allow_list", AllowList: []string{"support@example.com"}}})
	if got, _ := c.Redact(context.Background(), text); got != "mailto:support%40example.com and mailto:[EMAIL]" {
		t.Errorf("got %q", got)
	}
}

func TestNormalizedViewFoldsLookalikes(t *testing.T) {
	text := "a–b c＠d é" // en dash, no-break space, fullwidth @, a letter that stays
	view, orig, ok := normalizedView(text)
	if !ok || view != "a-b c@d é" {
		t.Fatalf("normalizedView(%q) = %q, %v", text, view, ok)
	}
	// a  –  b  nbsp  c  ＠  d  ' '  é(2 bytes)  end
	want := []int{0, 1, 4, 5, 7, 8, 11, 12, 13, 14, 15}
	if len(orig) != len(want) {
		t.Fatalf("orig = %v, want %v", orig, want)
	}
	for i := range want {
		if orig[i] != want[i] {
			t.Fatalf("orig = %v, want %v", orig, want)
		}
	}
	// Escapes and look-alikes compose: an en dash that arrives percent-encoded.
	if view, orig, ok := normalizedView("1%E2%80%932"); !ok || view != "1-2" || orig[1] != 1 || orig[2] != 10 || orig[3] != 11 {
		t.Errorf("normalizedView of an encoded en dash = %q %v %v", view, orig, ok)
	}
	// The em dash is a sentence's own punctuation, and accents are not look-alikes.
	for _, plain := range []string{"9999—verified", "café naïve", "Order 12 shipped"} {
		if _, _, ok := normalizedView(plain); ok {
			t.Errorf("normalizedView(%q) = ok, want no view", plain)
		}
	}
}

// Documents pasted from a word processor or PDF keep the dash and the space
// they were typeset with; the value must still be found, masked whole, and a
// hyphenated identifier must still not be an SSN.
func TestRedactUnicodeLookalikes(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"SSN 219–09–9999 ok", "SSN [SSN] ok"},
		{"SSN 219‑09‑9999 ok", "SSN [SSN] ok"},
		{"Tel 415–555–0173.", "Tel [PHONE]."},
		{"Card 4111 1111 1111 1111 ok", "Card [CREDIT_CARD] ok"},
		{"ＳＳＮ：２１９－０９－９９９９ ok", "ＳＳＮ：[SSN] ok"},
		{"mail jane.doe＠example.org now", "mail [EMAIL] now"},
		{"SSN%3A+219%E2%80%9309%E2%80%939999&x", "SSN%3A+[SSN]&x"},
		{"Order ORD–123–45–6789 shipped", "Order ORD–123–45–6789 shipped"},
		{"219—09—9999 and 3–5 pages", "219—09—9999 and 3–5 pages"},
		// Read as given, the em dash after the value is punctuation.
		{"SSN 219-09-9999—verified", "SSN [SSN]—verified"},
	} {
		if got, _ := New().Redact(context.Background(), c.in); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Invisible characters inside a value, digits of other scripts and the rarer
// look-alikes hide it from a reader of the text as given; the value must still
// be masked whole, and a mark that is a hyphen only inside a number stays
// itself in words.
func TestRedactInvisiblesAndScriptDigits(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"mail jane.\u200bdoe@example.org now", "mail [EMAIL] now"},
		{"mail jane.doe@example.or\u200bg now", "mail [EMAIL] now"},
		{"SSN 219\u200b-09-9999 ok", "SSN [SSN] ok"},
		{"Card 4111\u00ad1111\u00ad1111\u00ad1111 ok", "Card [CREDIT_CARD] ok"},
		{"Tel 415-555-01\u200d73 ok", "Tel [PHONE] ok"},
		{"SSN 21\u20609-09-9999 ok", "SSN [SSN] ok"},
		{"\ufeffSSN 219-09-99\u200c99 ok", "\ufeffSSN [SSN] ok"},
		{"SSN ٢١٩-٠٩-٩٩٩٩ ok", "SSN [SSN] ok"},
		{"SSN ۲۱۹-۰۹-۹۹۹۹ ok", "SSN [SSN] ok"},
		{"Phone: ४१५-५५५-०१७३ ok", "Phone: [PHONE] ok"},
		{"mail jane.doe﹫example.org now", "mail [EMAIL] now"},
		{"SSN 219ー09ー9999 ok", "SSN [SSN] ok"},
		{"SSN 219⁃09⁃9999 ok", "SSN [SSN] ok"},
		{"Order ORD-١٢٣-٤٥-٦٧٨٩ shipped", "Order ORD-١٢٣-٤٥-٦٧٨٩ shipped"},
		{"219—09—9999 and 219―09―9999", "219—09—9999 and 219―09―9999"},
	} {
		if got, _ := New().Redact(context.Background(), c.in); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// A dropped character has no byte in the view, and the sound mark is a
	// hyphen only between digits.
	if view, orig, ok := normalizedView("a\u00adb ー ٣ー٤"); !ok || view != "ab ー 3-4" || orig[1] != 3 {
		t.Errorf("normalizedView = %q %v %v", view, orig, ok)
	}
}

// A logged JSON body hides its values behind string escapes: a value after \n
// has no word boundary, and one escaped into a string field sits behind \".
// Each must be masked whole, with the escape before it kept, so the JSON
// stays valid; a backslash that is itself escaped is not one.
func TestRedactJSONEscapedValues(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`{"note":"x\n219-09-9999"}`, `{"note":"x\n[SSN]"}`},
		{`"Email:\njane.doe@example.org"`, `"Email:\n[EMAIL]"`},
		{`"Tel:\t415-555-0173\r\n"`, `"Tel:\t[PHONE]\r\n"`},
		{`{"ssn":"219–09–9999"}`, `{"ssn":"[SSN]"}`},
		{`{"ssn":"219\u201309\u20139999"}`, `{"ssn":"[SSN]"}`},
		{`{"dob":"03\/14\/1985"}`, `{"dob":"[DOB]"}`},
		{`{"body":"{\"ssn\":\"078051120\",\"dob\":\"1985-03-14\",\"phone\":\"4155550173\",\"mrn\":\"4481920\"}"}`,
			`{"body":"{\"ssn\":\"[SSN]\",\"dob\":\"[DOB]\",\"phone\":\"[PHONE]\",\"[MRN]\"}"}`},
		{`{"email":"m\u00fcller@example.de"}`, `{"email":"[EMAIL]"}`},
		{`{"email":"jane\u0040example.org"}`, `{"email":"[EMAIL]"}`},
		{`"a\u0020jane@example.org \ud83d\ude00"`, `"a\u0020[EMAIL] \ud83d\ude00"`},
		// \\n is a backslash and an n: the n is glued to the number.
		{`"x\\n219-09-9999"`, `"x\\n219-09-9999"`},
	} {
		got, _ := New().Redact(context.Background(), c.in)
		if got != c.want {
			t.Errorf("Redact(%s) = %s, want %s", c.in, got, c.want)
		}
		if !json.Valid([]byte(got)) {
			t.Errorf("Redact(%s) = %s, not valid JSON", c.in, got)
		}
	}
	// A surrogate pair is one character, mapped back onto its whole escape.
	view, orig, ok := normalizedView(`a\ud83d\ude00b`)
	if !ok || view != "a\U0001F600b" || orig[1] != 1 || orig[4] != 1 || orig[5] != 13 || orig[6] != 14 {
		t.Errorf("normalizedView of a surrogate pair = %q %v %v", view, orig, ok)
	}
	for _, plain := range []string{`C:\Windows`, `a\`, `\u00`, `\x41`, `\ud83d alone`} {
		if _, _, ok := normalizedView(plain); ok {
			t.Errorf("normalizedView(%q) = ok, want no view", plain)
		}
	}
}
