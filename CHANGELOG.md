# Changelog

## Unreleased

### Added

- **Presidio:** `Language` (default `"en"`, sent with each request and declared by the pack's
  recognizers), `HTTPClient` (default `http.DefaultClient`) and `MaxChars` (default
  `DefaultPresidioMaxChars`, 1,000,000, spaCy's `max_length`) fields. Text over `MaxChars` is not
  sent; `Detect` returns an error, so the caller fails closed instead of meeting a sidecar 500.
- **Examples:** runnable godoc examples for the quickstart (`Chain.Redact`), `Mask`,
  `Regex.SetPatternPack` and an allow list via `Chain.SetPatternPack`. Each is a test.

### Fixed

- **Presidio:** a URL with a trailing slash posted to `//analyze` and failed. The slash is now
  dropped. A non-200 reply was reported as a bare status with its body unread; the error now quotes
  up to 512 bytes of it, and the rest is drained so the connection can be reused.
- **Presidio:** `PresidioEntityMap` was read on every `Detect`, a data race with a caller editing it.
  `NewPresidio` now copies it; a later edit reaches only the instances built after it.

- **SSN, PHONE, MRN, DOB:** a verb between label and value hid the value: `My SSN is 078051120`,
  `MRN is 4481920`, `her date of birth is 1985-03-14`, `my phone number is 4155550173` were missed.
  One `is` or `was` (also `is:`) may now sit between them. `confirmation number is 483920571`
  stays: `number` alone is not a label.
- **SSN, PHONE, MRN, DOB:** common labels were missing: `SS#`, `Soc Sec #`, `ssnNumber`,
  `ssn_number`; `Ph:`, `cellphone`, `mobileNo`, `contactNumber`; `MR#: 4481920`; and `dob` after a
  camelCase hump (`patientDob`, `memberDOB`). `SS` and `MR` count only with their `#`, so a bare
  `SS` or the title `Mr` before a number does not.
- **DOB:** after a birth label, a timestamp was missed or half-masked: `{"dob":"1985-03-14T00:00:00Z"}`
  (how Go marshals a `time.Time`) was missed, and `DOB: 1985-03-14 00:00:00` left the time in the
  clear. The time and zone are now masked with the date. Compact `YYYYMMDD` (`{"dob":"19850314"}`)
  is now read too, month 01–12 and day 01–31. Unlabelled, neither shape is claimed.
- **MRN:** a value with a letter prefix (`MRN: E1234567`) or internal hyphens (`MRN: 12-345-678`)
  was missed. Both are read after the label, still 6–10 digits; spaces inside the value are not, so
  `MRN: 4481920 12 visits` does not take the count.
- **Chain:** a `Chain{}` with no detectors returned the text in the clear with no error:
  `(&Chain{}).Redact(ctx, "ssn 078-05-1120")` gave back the SSN. It now runs the built-in regex
  floor in their place and reports the new `ErrNoDetectors`, so it gives `ssn [SSN]` and the error.
- **Regex, Presidio:** a zero `Regex` panicked on `Detect`; it now reads with the built-in
  recognizers. A zero `Presidio` panicked on its nil HTTP client; it now uses `http.DefaultClient`
  and reports the failed request.
- **Regex:** the floor ignored its context: 4 MB with an already-cancelled context ran 2.5 s and
  returned no error. It now stops between recognizers and between the as-given and normalized
  reads, returning the spans found so far with the context's error, and the chain masks those spans
  as well as reporting it. Callers should fail closed on any error. `Chain.Timeout` does not apply
  to the floor: it bounds the other detectors, and a large text is still read to the end.
- **Allow list:** `support+billing@example.com` allow-listed for `EMAIL` came out as
  `support+[EMAIL]`, because the `+`-as-space reading claimed `billing@example.com`, which is not
  the allowed string. A claim of the same type wholly inside an allowed span is now dropped with it;
  a different value beside the allowed term is still masked.
- **Chain:** a span with offsets outside the text — from a custom detector — panicked a type guard,
  or merged with the floor's valid spans into a union `Mask` skipped, leaving all of them in the
  clear with no error. Such spans are now dropped and reported as that detector's error.
- **Chain:** a zero `Timeout` gave every detector an already-expired context, so a `Chain` literal
  without one could never reach a Presidio sidecar. Zero now means `DefaultTimeout`.
- **Mask:** overlapping spans left fragments of the earlier one unredacted. They are now merged
  first, as `Chain.Run` does. `Mask` is also a single pass: 20k spans in 380 KB went from 0.8 s
  and 7.9 GB allocated to 0.6 ms.
- **Presidio:** a regex rule with no `Confidence` scored 0.75 in the regex engine but reached
  Presidio as score 0, under every gate, so it never fired there.
- **New / NewRegex:** the built-in regexes are compiled once, not on every call; the quickstart's
  `piidetect.New().Redact(…)` is 3.6× faster and allocates 49× less.
- **EMAIL:** an address with a non-ASCII letter was missed or partly masked (`müller@example.de`
  became `mü[EMAIL]`), because RE2's `\b` and the character classes were ASCII-only. Latin, Greek
  and Cyrillic letters now count; an address glued to CJK or Thai text does not absorb it.
- **IBAN:** two printed IBANs in a row lost the second, because the search resumed after the first
  one's untrimmed greedy match. The type guard also dropped a correct hyphen-grouped IBAN from the
  Presidio tier.
- **DOB:** a birth label followed by `>` or `|` (`<dob>3/14/1985</dob>`, `dob|14.03.1961`), a FHIR
  XML `<birthDate value="…"/>`, or a line break after `Date of Birth:` voided the date. `14-Mar-1985`,
  `02-JAN-55`, `14th March 1985` and `1985/03/14` were missed after a label.
- **PHONE:** international numbers with a bracketed area code (`+55 (11) 91234-5678`) were missed.
- **SSN, PHONE, CREDIT_CARD:** a label joined to its value by a hyphen (`SSN-219-09-9999`,
  `Tel-415-555-0173`, `CC-4111-…`) was rejected as a hyphenated identifier.
- **MRN:** camelCase keys (`patientMrn`, `<PatientMRN>`) were rejected as the tail of a longer word.
- **MRN:** a two-character separator (`MRN--4481920`, `MRN:-4481920`) was missed.
- **MRN, DOB:** a Unicode space between label and value (U+2009, U+202F, U+3000, U+2007, as pasted
  from documents) was missed; only space, tab and U+00A0 counted.
- **DOB:** a date glued to its birth cue (`DOB03/14/1985`, `dob1985-03-14`) was missed, and the
  plural cues `DOBs`, `birthdates` and `birthdays` were not cues.
- **DOB:** a run of spaces inside a cue (`born  on`, `birth` U+00A0 `date`) voided it, and `birth day(s)`
  was not a cue.
- **SSN, PHONE:** an unformatted value right after its label was missed, so a JSON payload
  `{"ssn":"078051120","phone":"4155550173"}` went out in the clear. Nine digits after an SSN label
  (`SSN:`, `"ssn":`, `memberSsn=`, `Social Security Number`) and ten after a phone label (`Phone:`,
  `"mobile":`, `homePhone=`, `Fax`) now count; unlabeled digit runs are still left alone.
- **MRN:** the long-form labels `Medical Record Number`, `Medical Record #`, `Med Rec No.` and the
  keys `medicalRecordNumber` / `medical_record_number` were not labels.

- **All types:** percent-encoded values from a URL query or form body (`jane.doe%40example.org`,
  `4111+1111+1111+1111`, `DOB%3A%203%2F14%2F1985`, `tel=%2B14155550173`) were missed. The floor now
  also reads the decoded text and maps spans back to the offsets of the text as given; text with no
  escape and no form-encoded space is read once, with no allocation. Allow-list terms match the
  encoded form of a term too.

- **IP:** IPv6 addresses were claimed only when the Presidio sidecar was in the chain, so the
  floor alone sent `2001:db8:85a3::8a2e:370:7334` and SMTP `[IPv6:…]` literals in the clear. The
  floor now finds full, `::`-compressed and IPv4-mapped addresses of three or more groups with a
  linear scan; MACs, WWNs, clock times and `std::string` are not addresses.

- **SSN, PHONE, CREDIT_CARD, IBAN, MRN, DOB, EMAIL:** values pasted from documents with Unicode
  look-alikes were missed: an en dash, non-breaking hyphen or minus sign as a separator
  (`219–09–9999`, `415‑555‑0173`), non-breaking, narrow and ideographic spaces between card or IBAN
  groups, and fullwidth forms (`ＳＳＮ：２１９－０９－９９９９`, `jane.doe＠example.org`). The normalized
  text is read as well as the original and spans are mapped back; the em dash is not folded, so
  `219—09—9999` and `ORD–123–45–6789` stay unclaimed.

- **All types:** a zero-width space, joiner or soft hyphen inside a value hid it or split it, so
  `jane.<U+200B>doe@example.org` came out `jane.<U+200B>[EMAIL]`, and `4111<U+00AD>1111…` and
  `219<U+200B>-09-9999` went out in the clear. Digits of other scripts (`SSN ٢١٩-٠٩-٩٩٩٩`,
  `۲۱۹-۰۹-۹۹۹۹`, `Phone: ४१५-५५५-०१७३`), the small `﹫` and a katakana `ー` between digits
  (`219ー09ー9999`) were missed. Invisible characters (U+00AD, U+200B–U+200D, U+2060, U+FEFF) are
  now dropped from the normalized text, every Unicode decimal digit reads as its ASCII digit, and
  `ー` and the hyphen bullet `⁃` read as a hyphen between digits only. The em dash and U+2015 are
  still not folded.

- **All types:** values inside JSON string escapes were missed or cut. A value after a literal `\n`
  had no word boundary (`{"note":"x\n219-09-9999"}` went out unchanged), an address after one lost
  its first letter to the escape (`"Email:\njane.doe@example.org"` became `"Email:\[EMAIL]"`,
  invalid JSON), `03\/14\/1985`, `m\u00fcller@example.de` and a body escaped into a string field
  (`{"body":"{\"ssn\":\"078051120\"}"}`) were missed. The floor now also reads the text with
  `\n \r \t \/ \" \\` and `\uXXXX` (surrogate pairs included) decoded, ahead of percent-decoding and
  folding, and a span read as given never starts on an escape's letter, so `Mask` keeps the JSON
  valid. `\\n` is a backslash and an `n`; text with no backslash escape is still read once.

- **All types:** values behind HTML character references or percent-encoded twice went out in the
  clear: `jane&#64;example.org`, `jane&#x40;example.org`, `4111&nbsp;1111&nbsp;1111&nbsp;1111`,
  `219&ndash;09&ndash;9999`, `&lt;dob&gt;3/14/1985&lt;/dob&gt;`, `?email=jane.doe%2540example.org`
  and a `redirect=` URL carrying `ssn%3D219%252D09%252D9999`. The normalized text now decodes
  numeric references and `&nbsp; &ndash; &minus; &hyphen; &commat; &period; &lt; &gt; &amp;
  &quot;` (the `;` required) after JSON escapes and before percent-decoding, so `&ndash;` reaches
  folding as an en dash, and percent-decodes again while a `%XX` remains, up to three rounds. Only
  the first round reads `+` as a space, so a literal `%25` elsewhere cannot turn
  `sum=219%2B09%2B9999` into an SSN. Spans cover the whole reference or escape; text with no `&`
  reference and no escape is still read once, with no allocation.

### Fewer false positives

- **CREDIT_CARD:** one in ten long numbers passes Luhn, and logs are full of them: epoch
  microseconds and nanoseconds, snowflake IDs, compact timestamps (`20260922143017`) and
  `0000 0000 0000 0000` were masked as cards. A card must now start with a digit some network
  issues from: not `0`, not `1` unless it is 15-digit UATP, and `2` only in the Mir (2200–2204)
  and Mastercard (2221–2720) ranges. This replaces the epoch-milliseconds and consecutive-years
  special cases, which it covers. The guard applies to every engine's claims.
- **EMAIL:** retina asset names in HTML and CSS (`logo@2x.png`, `icon@3x.jpg`) were masked as
  addresses; an image extension is not a top-level domain.
- **CREDIT_CARD:** epoch-millisecond timestamps (`1727049600007`), one in ten of which passes Luhn.
- **PHONE:** NANP numbers whose area code or exchange starts with 0 or 1 (`123-456-7890`).
- **SSN:** numbers the SSA never issues (area `000` or `666`, group `00`, serial `0000`).
- **CREDIT_CARD:** four consecutive years in card layout (`visits 2023 2024 2025 2026`), one run
  in five of which passes Luhn.
- **IP:** Chrome's User-Agent version (`Chrome/120.0.0.0`) was masked as an address on nearly every
  request log. A dotted quad right after a `Name/` product token that starts at a space, `(` or
  the start of the text is a version; one in a URL path (`/api/clients/10.1.2.3`) is still an
  address. The guard applies to every engine's claims.
- **DOB:** an unlabelled `MM/DD/YYYY` followed by a clock time (`10/22/2026 14:30:17 INFO …`), or at
  either end of a range joined by `-`, `to`, `and`, `through` or `until` (`between 01/01/2026 and
  06/30/2026`). A date after a birth label is claimed as before, time or not.
- **PHONE:** signed counters and offsets (`delta=+1500000000`, `offset +1048576000`,
  `+1727049600007`) were claimed as E.164. A `+1` number must now be exactly ten digits after the
  `+1` and pass the NANP check; other country codes are unchanged.
- **EMAIL:** code: a method call (`y = A@np.linalg.inv(B)`) and an SSH or scp remote
  (`git@github.com:org/repo.git`), whose `:` is followed, with no space, by a path holding a `/` or
  ending `.git`. An address that ends a clause (`email jane@example.org: call her`) still counts.

### Faster

- **Regex:** a recognizer is skipped on text that cannot hold its match — no `@` for EMAIL, no cue
  word for an unlabelled-shape SSN, PHONE or DOB, no label for MRN — with the literals derived from
  the regexes and cue tables and checked on the normalized text too; clean text reads about 3x
  faster (1 MB prose 355→105 ms) and `bench_test.go` tracks it.

## v0.1.1 — 2026-09-23

Values written the way people actually type or print them were silently left unredacted. This
release fixes that across the built-in recognizers, and makes the test that should have caught it
strict.

### Fixed

- **MRN:** `MRN: 4481920` (colon *and* space) was not matched, because the separator slot held one
  character. Now also `MRN#`, `MRN No.`, `MRN - `, padded or tab-aligned values, and JSON, query
  and snake_case keys (`"mrn": "4481920"`, `mrn=4481920`, `patient_mrn: 4481920`). A line break
  is crossed only after an explicit separator, so a table header ending in `MRN` does not claim
  the next row's first number.
- **PHONE:** `1-800-555-0199` (a bare trunk `1`) was missed entirely, as were international
  numbers as printed (`+44 20 7946 0958`). The tail of a longer digit run (`Ref 98765-432-1098`)
  was claimed as a phone.
- **CREDIT_CARD:** a card followed by an expiry or CVV (`4111 1111 1111 1111 12/27`) was missed.
- **IBAN:** the printed, space-grouped form and lowercase entry were missed, and the type guard
  dropped a correct spaced or lowercase IBAN claimed by the Presidio tier. Registered countries
  are now also held to their registered length.
- **IP:** the type guard judged Presidio's IPv6 and CIDR spans more or less at random, and four
  fields of an OID (`1.3.6.1.4.1.311`) were claimed as an address.
- **DOB:** after a birth label, unpadded, dash- or dot-separated, day-first, two-digit-year, ISO
  and month-name dates are now claimed. Unlabeled, only `MM/DD/YYYY` is, as before.
- **EMAIL:** an apostrophe in the local part (`o'brien@example.com`) left `o'` in the output.
- **SSN, PHONE, CREDIT_CARD:** a value followed by `--` or `- ` (a dash in prose) was rejected as
  glued to a hyphenated identifier.
- **Chain:** the regex floor merged its own hits before the chain's type guards ran, so a valid value
  unioned with an overlapping claim of another type could fail its guard and be dropped whole. The
  chain now guards each claim first and merges once. `Regex.Detect` still returns merged spans.

### Tests

- The corpus test failed only on aggregate recall and precision floors, which tolerated one silent
  miss: the corpus already contained `MRN: 86753090`, and the test passed. Now every missed or
  partly covered value, and every unmarked claim, fails on its own.

## v0.1.0 — 2026-09-10

First extraction from the redaction gateway in air-traffic.
