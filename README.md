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

A regex that matches the *shape* of an SSN will happily claim an order number. Every built-in type
whose validity is checkable gets a validator, applied to every span regardless of which detector
claimed it:

| Type | Recognized | Confirmed by |
|---|---|---|
| `SSN` | `123-45-6789`, `123 45 6789` | not glued to a hyphenated identifier |
| `CREDIT_CARD` | 13–19 digits, spaced or dashed | Luhn checksum + hyphen adjacency |
| `IBAN` | ISO 13616 shape | mod-97 check digits |
| `IP` | dotted quad | octet range, no leading zeros |
| `EMAIL` | RFC-ish local@domain.tld | — |
| `PHONE` | NANP, E.164 | hyphen adjacency |
| `MRN` | `MRN-1234567` and variants | — |
| `DOB` | `MM/DD/YYYY` | month 01–12, day 01–31 (range only, not calendar-aware) |

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

Allow-list entries suppress a specific term for a specific type, matched case-insensitively on the
span's own text. They suppress the term, never a region of the document — so an allow-listed value
cannot be used to smuggle real PII past the filter by sitting next to it.

## What it does not do

Stated plainly, because the failure mode of a redaction library is silent under-detection:

- **Bare 9-digit SSNs** (`078051120`) are not matched. The false-positive rate against order
  numbers, account numbers, and zip+4 runs was not worth it.
- **Bare MRNs** without an `MRN` prefix are not matched, for the same reason.
- **Names, addresses, and free-text PHI** are not matched by the regex floor at all. That is what
  the Presidio tier is for.
- **Spans are byte offsets.** Presidio results are converted from codepoints on the way in.
- **Masking is not reversible.** `Mask` replaces a span with `[TYPE]`; there is no detokenization.

If you need a guarantee rather than a filter, do not use a filter.

## Status

Extracted from the redaction gateway in
[air-traffic](https://github.com/jchigg2000-git/air-traffic), where it runs inline on proxied
requests. Zero external module requirements — `go list -m all` returns only this module, and CI
enforces that. Test coverage is 92.6%, including a golden corpus of marked-up cases with explicit
traps that must *not* be detected.

## License

MIT
