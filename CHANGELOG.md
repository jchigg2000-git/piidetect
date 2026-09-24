# Changelog

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
