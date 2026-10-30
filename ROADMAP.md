# piidetect — ROADMAP

> ⭐ **SINGLE SOURCE OF TRUTH.** On any handoff or fresh session, **read this first and follow
> only this** for what's left, what's next, phases, acceptance criteria, and decisions. There are
> **no other `*_PLAN` / handoff / decision-log docs** — they were consolidated into this file. If another doc's
> status ever conflicts with this one, **this wins.**
>
> - **Reference / spec** (opened on demand, never as "the plan"): `README.md` (what it detects and
>   what it deliberately does not), `CHANGELOG.md` (what shipped).

> **Closed work is not in this file.** An item is deleted at the edit that closes it — there is
> no ✅ status. What shipped is recorded by the closing commit and `CHANGELOG.md`. To resurrect
> or cite a deleted item: `git log -S'<ID>' -- ROADMAP.md`, then `git show <sha>:ROADMAP.md`.

**Legend:** ⏳ in progress · ⬜ not started · 🔶 shipped but UNVERIFIED · 🔬 verification owed ·
⛔ **BLOCKS** — the only marker that gates anything. Superseded/rejected work survives only as a
one-line struck entry in the open-decisions index.

> **Backlog items are not blockers.** No item under a `BACKLOG` / `PARKED` status may be cited as
> gating, blocking, or holding up any other work unless it carries a `⛔ BLOCKS:` line with the
> owner's verbatim instruction. Absent that line, treat it as non-blocking. An agent that reports
> a parked item as a blocker is misreading this file.

**Contents:** §0 Do next · §1 Encodings (ENC) · §2 Precision (FP) · §3 Recall (REC) ·
§4 Robustness & API (API) · §5 Performance (PERF) · §6 Measurement (MEAS) · §7 Release (REL) ·
§8 Open-decisions index · Appendix

Every item below came from the 2026-10-30 survey (five read-only reviewers, one lens each:
recall, precision, encodings, API/perf, measurement). Each finding was reproduced by running it
against a temp copy at `8b02d83`; the input quoted on an item is the reproduction.

---

## §0 Do next

> ### ▶ RESUME HERE — session handoff 2026-10-30
>
> **State:** `main` clean, `go test ./... -race` green; round 1 shipped (below). Public repo; tags
> `v0.1.0`, `v0.1.1` — nothing tagged this session.
>
> **▶ NEXT ACTION: round 2 — REC-1+REC-2, REC-3+REC-4, ENC-3+ENC-4, PERF-1, API-2+API-3 in parallel worktrees; MEAS-2 inline.**
>
> #### What shipped
> Round 1: MEAS-1 per-type corpus scorer + IBAN/IPv4 traps + `Redact` end-to-end check; ENC-2
> zero-width/soft-hyphen dropped, every script's digits, `﹫`, `ー`; ENC-1 JSON string escapes;
> FP-1 UA versions, log-timestamp/range dates, `+1` counters, code emails; API-1 `ErrNoDetectors`,
> safe zero values, ctx checks in the floor, allow-listed plus-addresses. Foreman follow-up: the
> chain's `Timeout` no longer cuts the regex floor (API-1 made a 4 MB text come back partly read
> under `DefaultTimeout`; `TestChainTimeoutDoesNotCutTheFloor`).
>
> #### What I found by reading that nobody reported
> ENC-1 trade-off: in a Windows path `C:\temp\nancy@example.org` the `\n` reads as an escape, so
> `ancy@example.org` is masked and the `n` stays. Documented in README; kept because the
> alternative (`"Email:\[EMAIL]"`) breaks every logged JSON body.
>
> #### What I deliberately did NOT do, and why
> Tagged nothing and skipped FP-2/FP-4/FP-6 and API-6/API-7b: the four owner questions below went
> unanswered (asked 2026-10-30, no reply in 5 min), and each is public or trades recall.
>
> #### Questions — each one line from you
> - Tag `v0.1.2` now from Unreleased? (REL-1; my pick: after round 1, i.e. now)
> - FP-2/FP-4: require a label for space-only SSN/phone shapes, adding `call`/`text` cues? (my pick: yes)
> - FP-6: tighten card issuer prefixes, losing 7xxx fleet and non-Troy 9xxx cards? (my pick: yes)
> - Open v0.2 for breaking API changes (API-6 error shape, API-7b `SetPatternPack` error, renames)?

---

## §1 Encodings (ENC)

The decode pass (`decode.go`) reads text twice — as given and normalized — and maps spans back.
Every stage added here must compose into `orig` the way `percentDecoded` does, and text with none
of the triggers is still read once.

- ⬜ **ENC-3** HTML entities — numeric (`&#64;`, `&#x40;`) and a small named set (`nbsp ndash minus
  hyphen commat lt gt amp quot`), gated on `&#` or `&`+known name. Repro: `jane&#64;example.org`,
  `4111&nbsp;1111&nbsp;1111&nbsp;1111` missed.
- ⬜ **ENC-4** Double percent-encoding — repeat `percentDecoded` up to 3 rounds while escapes remain.
  Repro: `?email=jane.doe%2540example.org` unchanged. Only risk: a literal `%25XX`.
## §2 Precision (FP)

Each fix only removes claims; the precision reviewer sketched FP-2…FP-4 together with the shipped
FP-1 and the corpus stayed green (every value caught, 0 traps). Each ships with its trap entry in `seed.json`.

- ⬜ **FP-3** Card layout — `\b\d(?:[- ]?\d){12,18}` (`regex.go:115`) claims `ids 42 17 88 93 12 55 61`;
  replace with `(\d{4}[- ]){3}\d{4}([- ]\d{3})?`. Changes `TestGuardsJudgeClaimsBeforeMerging`'s
  expected output (`Wire [IBAN] 106 EUR`); give it a new input that still exercises guard-before-merge.
- ⬜ **FP-2** Space-separated SSN without a label — `"GET /api HTTP/1.1" 200 12 4096` → `[SSN]`; `123+45+6789`
  after `+` folding (`regex.go:78`, `decode.go:100`). Fix: a spaced match needs an SSN label.
  Cost: `SSN on file 123 45 6789` missed. **Owner call** — see §8.
- ⬜ **FP-4** Space-only 3-3-4 phone shapes — `sizes 512 768 1024`, `dims 640 480 1920` → `[PHONE]`.
  Fix: spaces-only separators need a phone label (add `call`/`text` cues). Cost: `call me at 415 555
  0173` risky without them. **Owner call** — see §8.
- ⬜ **FP-6** Issuer prefixes — `ports 8080 8443 9090 3000` → `[CREDIT_CARD]` (Luhn passes). Reject
  leading 31–33, 7, 8 other than 81/82, 9 other than 9792 (`issuable`, `regex.go:538`). Cost: 7xxx
  fleet and other 9xxx national cards missed. **Owner call** — see §8.

## §3 Recall (REC)

Label-cued only; none of these widens an unlabelled shape.

- ⬜ **REC-1** `is`/`was` between label and value — `My SSN is 078051120`, `MRN is 4481920`,
  `her date of birth is 1985-03-14` missed. `labelledBy` (`regex.go:439`) strips one trailing
  ` is`/` was`; MRN regex (`regex.go:147`) takes the same optional word. `trap_order_bare9` must hold.
- ⬜ **REC-2** Missing labels — `patientDob`/`memberDOB` (make `dob` `cueWordOrHump`, `regex.go:401`),
  `SS#:`, `Soc Sec #:`, `ssnNumber`, `ssn_number`, `Ph:`, `cellphone`, `mobileNo`, `contactNumber`,
  `MR#: 4481920` (`#` required so the title "Mr" can't match).
- ⬜ **REC-3** DOB as timestamp or compact — `{"dob":"1985-03-14T00:00:00Z"}` (Go's `time.Time`
  marshalling) missed; `DOB: 1985-03-14 00:00:00` leaves the time; `{"dob":"19850314"}` missed.
  After a cue only.
- ⬜ **REC-4** MRN with letter prefix or hyphens — `MRN: E1234567`, `MRN: 12-345-678` missed
  (`regex.go:147`). After the label only; no internal spaces.
- ⬜ **REC-5** Medicare MBI as a new type — `MBI: 1EG4-TE5-MK73` missed. Dashed form anywhere, undashed
  only after `MBI`/`Medicare`, per-position validator; trap an uppercase 11-char request ID.

## §4 Robustness & API (API)

- ⬜ **API-2** Runnable godoc Examples — `ExampleChain_Redact` (quickstart), `ExampleMask`,
  `ExampleRegex_SetPatternPack`, allow-list. None exist.
- ⬜ **API-3** Presidio client, non-breaking part — trailing-slash URL gives `//analyze`
  (`presidio.go:110`); non-200 body neither drained nor quoted (`:120`); language hard-coded `"en"`
  (`:100`); injectable `*http.Client`; max-chars guard (spaCy default 1M); `PresidioEntityMap` global
  read in `Detect` is a race if mutated — copy per instance.
- ⬜ **API-4** Adoption, additive — per-type enable/disable (the ask-meadowlark port forked to drop
  uncued DOB), `MaskFunc func(Span, string) string` (+ HMAC pseudonymization Example), exported
  `Type…` constants, `Chain.SetPatternPack` forwarding to each detector.
- ⬜ **API-6** Error shape (breaking) — `Run`/`Redact` return `[]error` (`api.go:33`,
  `piidetect.go:130`); move to one `error` via `errors.Join` of `*DetectorError` + `ErrSpanOutOfRange`.
  Waits on the v0.2 call, §8.
- ⬜ **API-7b** Breaking cleanups for v0.2 — `Presidio.SetPatternPack` returns `error`; unexport
  `RuneToByteOffsets`; rename `WithPresidio`. Waits on the v0.2 call, §8.

### Parked ideas
- 💭 Streaming `io.Reader` with overlapping windows; walking JSON document values. Large; after v0.2.

## §5 Performance (PERF)

Baseline at `8b02d83` (Apple M5): ~2.5–3 MB/s; 1 KB log line 430 µs, 100 KB JSON 40 ms, 1 MB 390 ms.
Profile is almost all `regexp`; clean and dirty input cost the same.

- ⬜ **PERF-1** Commit `bench_test.go` (1 KB log, 100 KB JSON, 1 MB text; clean, dirty, clean+`%20`,
  clean+NBSP) and skip recognizers whose required literal is absent (`@` for EMAIL; cue words for
  unformatted SSN/PHONE, MRN, labelled DOB — the labelled-DOB regex alone is 172 of ~400 µs/KB,
  `regex.go:155-166`). Prototype: 1 KB 430→144 µs, 1 MB 390→166 ms, corpus green.
- ⬜ **PERF-2** One `%20` or NBSP rescans the whole text (1 KB 430→751 µs; 1 MB 390→790 ms) — rescan
  bounded windows around decoded/folded bytes. After ENC-1…ENC-4 land, since they add stages.

## §6 Measurement (MEAS)

Corpus at `8b02d83`: 81 entries, 113 floor values, 3 Presidio-only, 49 traps; coverage 94.9%.

- ⬜ **MEAS-2** CI — pinned `staticcheck` via `go run` (clean today, no go.mod change); Go matrix
  `['1.22','stable']`; enforce the README's "over 90%" coverage or drop the number (README:160).
  govulncheck only non-blocking on stable (14 stdlib findings, toolchain-owned).
- ⬜ **MEAS-3** Corpus shapes — entries are short (median 66 chars), 4 multi-line, 1 code, 0 real table
  rows. Add a structured log line, a CSV row under its header, a multi-paragraph clinical note with
  visit-date traps, a code snippet with hex constants; optional `shape`/`targets` fields.
- ⬜ **MEAS-4** Port parity — TODO.md's "55 of 55" (ask-meadowlark port) was scored at `d04df64` on a
  56-entry corpus; it is stale at 81. Optional per-entry JSON results flag so the port can diff.

## §7 Release (REL)

- ⬜ **REL-1** Cut `v0.1.2` — exported API unchanged since `v0.1.1`; Unreleased fixes a Chain panic,
  the zero-`Timeout` Presidio bug, quadratic `Mask`, per-call regex compile. Tagging is public:
  owner's call, §8.
- ⬜ **REL-2** README states cost per KB for request-path users once PERF-1 lands.

## §8 Open-decisions index

- **REL-1** tag `v0.1.2` now? → §7
- **FP-2 / FP-4** label required for space-only SSN and phone shapes? → §2
- **FP-6** tighter card issuer prefixes? → §2
- **API-6 / API-7b** open v0.2 for breaking changes? → §4
- **REC-5** add MBI as a type? → §3
- ~~Bare line break between label and value, column-gap exception~~ **killed 2026-09-27:** unsafe; sends double-spaced and list wordings (folded TODO.md).
- ~~Bare 9-digit SSN, 10-digit phone, bare MRN, uncued non-MM/DD dates~~ **killed 2026-10-30:** existing traps show the precision cost.
- ~~Fold em dash / U+2015~~ **killed 2026-10-30:** sentence punctuation.
- ~~`(at)`/`dot` email obfuscation, dotted cards/SSNs~~ **killed 2026-10-30:** precision cost too high.
- ~~`Patient ID` / `Acct #` labels~~ **killed 2026-10-30:** nothing to validate; pattern-pack territory.
- ~~Retries in the Presidio client~~ **killed 2026-10-30:** runs inline under a 2 s budget.

## Appendix — consolidation history

- `TODO.md` (59 lines, notes from the ask-meadowlark TypeScript port; live item → MEAS-4, withdrawn
  column-gap suggestion → §8 struck line, divergences are port-side reference) — `git show 8b02d83:TODO.md`
- Not migrated: the port's divergence notes (uncued DOB removed there, comma after DOB cue, ZIP
  recognizer, fail-closed on out-of-range spans) — reference about another repo, recoverable above.
- Stays separate: `README.md` (spec of behavior and deliberate gaps), `CHANGELOG.md` (history).
