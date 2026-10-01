# Changelog

## Unreleased

### Fixed

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
