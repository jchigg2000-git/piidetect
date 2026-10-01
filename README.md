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
| `SSN` | `123-45-6789`, `123 45 6789`, `SSN-123-45-6789`; unformatted (`078051120`) only after an SSN label (`SSN:`, `"ssn":`, `memberSsn=`, `Social Security Number`) | never-issued numbers (area `000`/`666`, group `00`, serial `0000`) rejected; not glued to a hyphenated identifier other than a label (`SSN-`, `Tel-`, `CC-`) |
| `CREDIT_CARD` | 13–19 digits, spaced or dashed; a following expiry or CVV does not hide it | Luhn checksum + hyphen adjacency + a network that could have issued it: a leading `0`, a leading `1` (other than 15-digit UATP) or a leading `2` outside the Mir and Mastercard ranges is not a card, which keeps epoch timestamps, snowflake IDs, compact timestamps (`20260922143015`) and `0000 0000 0000 0000` out |
| `IBAN` | electronic (`DE89370400440532013000`, any case) and printed (`DE89 3704 0044 0532 0130 00`); hyphen-grouped when the Presidio tier claims it | mod-97 check digits + the country's registered length |
| `IP` | dotted quad; IPv6 of three or more groups, full or `::`-compressed (`2001:db8:85a3::8a2e:370:7334`, `[IPv6:2606:4700:4700::1111]`, `::ffff:192.0.2.1`), found by a linear scan; CIDR when the Presidio tier claims it | octet range, no leading zeros, not part of a longer dotted run such as an OID; IPv6 must parse, and a MAC or WWN, a C++ scope (`std::string`), a clock time or `::1` is not one |
| `EMAIL` | RFC-ish local@domain.tld, in Latin, Greek or Cyrillic letters (`müller@münchen.de`) | an image asset name (`logo@2x.png`) is not an address |
| `PHONE` | NANP (with or without `+1` / `1-`), E.164, and international numbers as printed (`+44 20 7946 0958`, `+55 (11) 91234-5678`); unformatted NANP (`4155550173`) only after a phone label (`Phone:`, `"mobile":`, `homePhone=`, `Fax`) | NANP: area code and exchange start 2–9, not part of a longer digit run, hyphen adjacency |
| `MRN` | the `MRN`, `Medical Record` or `Med Rec` label then 6–10 digits: `MRN-1234567`, `MRN: 1234567`, `MRN# 1234567`, `MRN No. 1234567`, `"mrn": "1234567"`, `mrn=1234567`, `patientMrn: 1234567`, `Medical Record Number: 1234567`, `"medicalRecordNumber": "1234567"` | the label must start a word or a camelCase hump; a line break is crossed only after a separator |
| `DOB` | `MM/DD/YYYY` anywhere; after a birth label (`DOB:`, `date of birth`, `born`, `birthDate`, `<dob>`, `<birthDate value="…">`) also unpadded, `-` or `.` separated, day-first, two-digit years, ISO, and month names (`14-Mar-1985`, `14th March 1985`) | month 01–12, day 01–31 (range only, not calendar-aware); the label for the other forms |

Query strings and form bodies are read twice, as given and decoded (`%XX` escapes, and `+` between
letters or digits as a space), so labels, separators and values are found whatever their encoding
(`mailto:jane.doe%40example.org`, `card=4111+1111+1111+1111`, `q=DOB%3A%203%2F14%2F1985`). Spans are
mapped back onto the text as given, so `Mask` replaces the whole encoded value. The price is that a
`+` is a space there: `123+45+6789` reads as an SSN. Text with neither is read once.

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

Presidio entity types are normalized onto this package's vocabulary via `PresidioEntityMap`, and its
results are gated at `PresidioDefaultScoreGate` (0.4) unless a threshold rule lowers it per type.

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
cannot be used to smuggle real PII past the filter by sitting next to it.

## What it does not do

Stated plainly, because the failure mode of a redaction library is silent under-detection:

- **Bare 9-digit SSNs** (`078051120`) are not matched unless an SSN label sits right before them.
  The false-positive rate against order numbers, account numbers, and zip+4 runs was not worth it.
- **Bare MRNs** without an `MRN` prefix are not matched, for the same reason. Neither is an `MRN`
  label with its value on the next line and no separator between them: a table header ending in
  `MRN` would otherwise claim the first number of the next row.
- **Dates other than `MM/DD/YYYY`** (`3/14/1985`, `1985-03-14`, `14.03.1985`) are only claimed as
  `DOB` right after a birth label. Unlabeled, they are almost always appointment, invoice, or log
  dates.
- **Bare 10-digit phone numbers** (`4155550173`) are not matched unless a phone label sits right
  before them, for the same reason as bare SSNs. As for MRN, a label's value on the next line is
  claimed only after a separator.
- **Unicode dashes** (non-breaking hyphen, en dash) as SSN or phone separators are not matched;
  the separator classes are ASCII.
- **Doubly encoded values, HTML entities and JSON `\u` escapes** (`jane.doe%2540example.org`,
  `jane&#64;example.org`, `jane\u0040example.org`) are not decoded. Single percent-encoding and
  form-encoded spaces are; see above. The Presidio tier reads the text as given.
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
traps that must *not* be detected. Every corpus value must be found and fully covered, and nothing
unmarked may be claimed; one miss fails CI.

## License

MIT
