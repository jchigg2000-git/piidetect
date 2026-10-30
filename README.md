# piidetect

Find and redact PII/PHI in text, in Go, with no dependencies.

Microsoft Presidio is the standard tool for this and it is Python. If your service is Go, your
options have been to stand up a Python sidecar for every redaction, or to write regexes and hope.
This is the third option: a fast in-process floor that validates what it finds, with the sidecar
demoted to optional.

```bash
go get github.com/jchigg2000-git/piidetect
```

## Quickstart

```go
package main

import (
	"context"
	"fmt"

	"github.com/jchigg2000-git/piidetect"
)

func main() {
	clean, _ := piidetect.New().Redact(context.Background(),
		"Member 078-05-1120 paid with 4111 1111 1111 1111; reach her at jane.doe@example.org.")
	fmt.Println(clean)
}
```

```
Member [SSN] paid with [CREDIT_CARD]; reach her at [EMAIL].
```

No network, no configuration, no sidecar. That example is a test (`TestReadmeQuickstart`), so if it
ever stops producing that string, CI fails.

## What it detects, and what confirms it

A regex that matches the *shape* of an SSN will happily claim an order number, so every built-in
type whose validity is checkable gets a validator. The `SSN`, `CREDIT_CARD`, `IBAN` and `IP` checks
are applied to every span regardless of which detector claimed it; the `PHONE`, `MRN` and `DOB`
checks belong to the regex floor's own recognizers:

| Type | Recognized | Confirmed by |
|---|---|---|
| `SSN` | `123-45-6789`, `123 45 6789`, `SSN-123-45-6789`; unformatted (`078051120`) only after an SSN label (`SSN:`, `"ssn":`, `memberSsn=`, `ssn_number`, `Social Security Number`, `Soc Sec #`, `SS#`; never a bare `SS`), optionally followed by `is` or `was` (`My SSN is 078051120`) | never-issued numbers (area `000`/`666`, group `00`, serial `0000`) rejected; not glued to a hyphenated identifier other than a label (`SSN-`, `Tel-`, `CC-`) |
| `CREDIT_CARD` | 13–19 digits, spaced or dashed; a following expiry or CVV does not hide it | Luhn checksum + hyphen adjacency + a network that could have issued it: a leading `0`, a leading `1` (other than 15-digit UATP) or a leading `2` outside the Mir and Mastercard ranges is not a card, which keeps epoch timestamps, snowflake IDs, compact timestamps (`20260922143015`) and `0000 0000 0000 0000` out |
| `IBAN` | electronic (`DE89370400440532013000`, any case) and printed (`DE89 3704 0044 0532 0130 00`); hyphen-grouped when the Presidio tier claims it | mod-97 check digits + the country's registered length |
| `IP` | dotted quad; IPv6 of three or more groups, full or `::`-compressed (`2001:db8:85a3::8a2e:370:7334`, `[IPv6:2606:4700:4700::1111]`, `::ffff:192.0.2.1`), found by a linear scan; CIDR when the Presidio tier claims it | octet range, no leading zeros, not part of a longer dotted run such as an OID, not a User-Agent product version (`Chrome/120.0.0.0`); IPv6 must parse, and a MAC or WWN, a C++ scope (`std::string`), a clock time or `::1` is not one |
| `EMAIL` | RFC-ish local@domain.tld, in Latin, Greek or Cyrillic letters (`müller@münchen.de`) | an image asset name (`logo@2x.png`), a method call (`A@np.linalg.inv(B)`) and an SSH remote followed by `:` and a path are not addresses |
| `PHONE` | NANP (with or without `+1` / `1-`), E.164, and international numbers as printed (`+44 20 7946 0958`, `+55 (11) 91234-5678`); unformatted NANP (`4155550173`) only after a phone label (`Phone:`, `Ph:`, `"mobile":`, `homePhone=`, `cellphone`, `mobileNo`, `contactNumber`, `Fax`), optionally followed by `is` or `was` | NANP: area code and exchange start 2–9, not part of a longer digit run, hyphen adjacency; a `+1` number has exactly ten digits after the `+1` |
| `MRN` | the `MRN`, `Medical Record`, `Med Rec` or `MR#` label, optionally followed by `is` or `was`, then 6–10 digits, optionally after a one- or two-letter prefix or joined by single hyphens (`MRN: E1234567`, `MRN: 12-345-678`; no spaces inside the value): `MRN-1234567`, `MRN: 1234567`, `MRN# 1234567`, `MR#: 1234567`, `MRN is 1234567`, `MRN No. 1234567`, `"mrn": "1234567"`, `mrn=1234567`, `patientMrn: 1234567`, `Medical Record Number: 1234567`, `"medicalRecordNumber": "1234567"` | the label must start a word or a camelCase hump; `MR` needs its `#`, so the title `Mr` never counts; a line break is crossed only after a separator |
| `DOB` | `MM/DD/YYYY` anywhere; after a birth label (`DOB:`, `patientDob`, `date of birth`, `born`, `birthDate`, `<dob>`, `<birthDate value="…">`, any of them optionally followed by `is` or `was`) also unpadded, `-` or `.` separated, day-first, two-digit years, ISO, ISO with a time and zone (`1985-03-14T00:00:00Z`, `1985-03-14 00:00:00`, masked whole), compact `YYYYMMDD` (`19850314`), and month names (`14-Mar-1985`, `14th March 1985`) | month 01–12, day 01–31 (range only, not calendar-aware); unlabelled, not followed by a clock time or one end of a date range; the label for the other forms |

Text that carries JSON string escapes, HTML character references, percent-encoding or look-alike
punctuation is read twice, as given and normalized: JSON escapes are decoded, so a value in a logged
body is read as the string it encodes (`"Email:\njane.doe@example.org"`, `03\/14\/1985`,
`m\u00fcller@example.de`, `{"body":"{\"ssn\":\"078051120\"}"}`; `\\n` stays a backslash and an
`n`), then HTML character references with their `;` (`jane&#64;example.org`, `&#x40;`, and
`&nbsp; &ndash; &minus; &hyphen; &commat; &period; &lt; &gt; &amp; &quot;`, so
`4111&nbsp;1111&nbsp;1111&nbsp;1111` and `&lt;dob&gt;3/14/1985` are read; `&amp;#64;` stays an
ampersand and `#64;`), then `%XX` escapes, with `+` between letters or digits a space (query
strings and form bodies: `mailto:jane.doe%40example.org`, `card=4111+1111+1111+1111`,
`q=DOB%3A%203%2F14%2F1985`), decoded again while an escape remains, up to three rounds
(`jane.doe%2540example.org`, a `redirect=` URL's own `ssn%3D219%252D09%252D9999`), and what a
document pasted from a word processor or PDF carries is folded onto ASCII: the Unicode dashes that
stand for a hyphen (`219–09–9999`, `415‑555‑0173`), non-breaking, thin and ideographic spaces
(`4111 1111 1111 1111`), fullwidth forms (`ＳＳＮ：２１９－０９－９９９９`), and the digits of other scripts
(`٢١٩-٠٩-٩٩٩٩`, `४१५-५५५-०१७३`). Zero-width characters and soft hyphens are dropped, so a value they
split (`jane.<U+200B>doe@example.org`) is read whole. Spans are mapped back onto the text as given,
so `Mask` replaces the whole value. The price is that a `+` is a space there: `123+45+6789` reads
as an SSN; a literal `%` written `%25` before two hex digits is decoded again (`100%2540` reads
`100@`); and a backslash before a letter is an escape there: in a Windows path
(`C:\temp\nancy@example.org`) the `n` stays and `ancy@example.org` is masked. Text with none of
these is read once.

So these are left alone:

```go
"Order ORD-123-45-6789 shipped"      // identifier, not an SSN
"ref 4111111111111112"               // fails Luhn, not a card
"version 10.0.256.1"                 // octet out of range, not an IP
```

Detection is RE2 — linear time, no catastrophic backtracking, safe to run on input you did not
author.

## Optional: the Presidio tier

Regex cannot find names, street addresses, or PHI buried in narrative text. When you need those,
point the chain at a self-hosted [presidio-analyzer](https://microsoft.github.io/presidio/):

```go
c := piidetect.WithPresidio("http://localhost:5002")
clean, errs := c.Redact(ctx, text)
```

The regex floor still runs first and still runs if the sidecar is down — a dead sidecar degrades to
regex-only and reports the error alongside the spans it did find. It never fails open and silently
returns your text unredacted.

To configure the client, build the chain yourself. Each field's zero value is the default:

```go
p := piidetect.NewPresidio("http://localhost:5002")
p.Language = "de"            // default "en"; the sidecar needs a model for it
p.HTTPClient = myClient      // default http.DefaultClient
p.MaxChars = 200_000         // default 1,000,000 (spaCy's max_length); negative for no limit
c := &piidetect.Chain{Detectors: []piidetect.Detector{piidetect.NewRegex(), p}}
```

Text over `MaxChars` is not sent: the sidecar would fail it anyway, so `Detect` reports an error
without the round trip and your fail-closed path takes over. A non-200 reply is reported with the start of its body
(the sidecar's own message), so a missing language model reads as one rather than as a bare `500`.

## Errors mean fail closed

`Run` and `Redact` return every span they found, but an error means one may have been missed: a
sidecar was down, a detector timed out, the caller's context ended (the floor stops between
recognizers once it is done, so a cancelled request comes back partly read), or the chain was
misconfigured. Where a leak matters, treat any error as failure — drop the text or mask all of it —
rather than send on the partial result. `Chain.Timeout` bounds the other detectors, not the regex
floor: several megabytes are read to the end however long that takes.

Zero values are safe: a `Chain{}` with no detectors runs the built-in floor in their place and
reports `ErrNoDetectors`, so `(&Chain{}).Redact(ctx, "ssn 078-05-1120")` gives `ssn [SSN]` and the
error, never the SSN. A zero `Regex` reads with the built-ins; a zero `Presidio` reports an error.

Presidio entity types are normalized onto this package's vocabulary via `PresidioEntityMap`, and its
results are gated at `PresidioDefaultScoreGate` (0.4) unless a threshold rule lowers it per type.
`NewPresidio` copies the map, so edit it before constructing: a later edit reaches only the
instances built after it.

## Extending it at runtime

`SetPatternPack` swaps in additional recognizers atomically, with no restart — regex rules, deny
lists, per-type score thresholds, and allow lists:

```go
regex := piidetect.NewRegex()
regex.SetPatternPack([]piidetect.PatternRule{
	{ID: "emp-id", Type: "EMPLOYEE_ID", Regex: `\bEMP\d{6}\b`, Confidence: 0.9},
})

chain := &piidetect.Chain{Detectors: []piidetect.Detector{regex}, Timeout: piidetect.DefaultTimeout}
chain.SetPatternPack([]piidetect.PatternRule{
	{ID: "not-ours", Type: "EMAIL", Kind: "allow_list", AllowList: []string{"support@example.com"}},
})
```

Presidio compiles a pack's regex rules with its own default flags, case-insensitive among them,
so the same rule can match more there than in the regex engine (`\bEMP\d{6}\b` also matches
`emp123456`). Write rules that mean the same thing under both.

Allow-list entries suppress a specific term for a specific type, matched case-insensitively on the
span's own text. They suppress the term, never a region of the document — so an allow-listed value
cannot be used to smuggle real PII past the filter by sitting next to it. A claim of the same type
lying wholly inside the allowed term goes with it: the floor reads `support+billing@example.com` with
`+` as a space too, and `billing@example.com` there is the term's own characters, not another value.

## What it does not do

Stated plainly, because the failure mode of a redaction library is silent under-detection:

- **Bare 9-digit SSNs** (`078051120`) are not matched unless an SSN label sits right before them.
  The false-positive rate against order numbers, account numbers, and zip+4 runs was not worth it.
- **Bare MRNs** without an `MRN` prefix are not matched, for the same reason. Neither is an `MRN`
  label with its value on the next line and no separator between them: a table header ending in
  `MRN` would otherwise claim the first number of the next row.
- **Dates other than `MM/DD/YYYY`** (`3/14/1985`, `1985-03-14`, `14.03.1985`, `19850314`,
  `1985-03-14T00:00:00Z`) are only claimed as `DOB` right after a birth label. Unlabeled, they are
  almost always appointment, invoice, or log dates.
- **Bare 10-digit phone numbers** (`4155550173`) are not matched unless a phone label sits right
  before them, for the same reason as bare SSNs. As for MRN, a label's value on the next line is
  claimed only after a separator.
- **The em dash and the horizontal bar** (U+2014, U+2015) are not folded: they are a sentence's
  punctuation, and `219—09—9999` stays.
- **Base64, quoted-printable and line-wrapped values** (`amFuZS5kb2VAZXhhbXBsZS5vcmc=`,
  `jane.doe=40example.org`, a number split across a line break) are not decoded or joined.
- **HTML entities past a short list, and encodings past their depth** are not decoded: named
  references other than the ten above (`&copy;`, `&apos;`), a reference without its `;`
  (`jane&#64example.org`), a value percent-encoded four times, and JSON escapes past one level (a
  body escaped twice, `{\\\"ssn\\\":…}`). A `+` that a second percent round finds came from `%2B`
  and stays a plus, so a form space encoded twice (`ssn%3D219%2B09%2B9999`) is not a space.
  The Presidio tier reads the text as given.
- **Email addresses written in scripts without spaces** (Chinese, Japanese, Thai) are not matched
  in those scripts: the address would absorb the words around it. ASCII addresses inside such
  text are.
- **IPv6 of fewer than three groups** (`::1`, `fe80::1`, `2001:db8::/32`) is not matched: with
  that few, `a::b` and `Bad::Dad` in code are indistinguishable from addresses. Loopback and
  link-local are not people.
- **Names, addresses, and free-text PHI** are not matched by the regex floor at all. That is what
  the Presidio tier is for.
- **Presidio entity types not in `PresidioEntityMap` are dropped**, among them `US_PASSPORT`,
  `US_BANK_NUMBER`, `US_DRIVER_LICENSE`, `UK_NHS` and `CRYPTO`, and so is `DATE_TIME`: an unmapped
  type would bypass the type guards. Add a type to the map to accept it.
- **Spans are byte offsets.** Presidio results are converted from codepoints on the way in.
- **Masking is not reversible.** `Mask` replaces a span with `[TYPE]`; there is no detokenization.

If you need a guarantee rather than a filter, do not use a filter.

## Status

Extracted from the redaction gateway in
[air-traffic](https://github.com/jchigg2000-git/air-traffic), where it runs inline on proxied
requests. Zero external module requirements — `go list -m all` returns only this module, and CI
enforces that. Test coverage is over 90%, including a golden corpus of marked-up cases with explicit
traps that must *not* be detected. Every corpus value must be found and fully covered by a span of
its own type and be gone from `Redact` output, and nothing else may be claimed; one miss fails CI.
`go test -v -run Corpus` prints the per-type table.

## License

MIT
