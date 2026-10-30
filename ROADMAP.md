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
> **State:** `main` clean, `go test ./... -race` green; rounds 1–2 shipped (below). Public repo;
> tags `v0.1.0`, `v0.1.1` — nothing tagged this session.
>
> **▶ NEXT ACTION: round 3 — FP-3, MEAS-3, API-4 (split a/b), PERF-2 in parallel worktrees; REL-2 + MEAS-4 inline.**
>
> #### What shipped
> Round 1 (`7dd64f8`…`4fa7ceb`): MEAS-1 per-type scorer + IBAN/IPv4 traps + `Redact` end-to-end;
> ENC-2 invisibles and every script's digits; ENC-1 JSON string escapes; FP-1 UA versions,
> log-timestamp dates, `+1` counters, code emails; API-1 fail closed on zero values/cancellation;
> `Chain.Timeout` no longer cuts the floor. Round 2 (`2abc80a`…`22c38af`): MEAS-2 CI matrix,
> staticcheck, coverage floor; API-2 Examples; API-3 Presidio `Language`/`HTTPClient`/`MaxChars`,
> trailing slash, per-instance entity map; REC-1/2 `is`/`was` and missing labels; REC-3/4 DOB
> timestamps/compact, prefixed/hyphenated MRNs; ENC-3/4 HTML references and double
> percent-encoding; PERF-1 literal skip (geomean −54%). Foreman follow-ups: a quoted Presidio
> error body is masked by the floor before it reaches the error (`df6daac`); the MRN finder is
> gated on its regex's literals (`22c38af`).
>
> #### What I found by reading that nobody reported
> API-3 quoted the sidecar's error body raw; callers log errors, so an echoing sidecar would have
> put PII in logs. Fixed as above. PERF-1 left the MRN recognizer ungated after REC-4 moved it to a
> hand-written finder; recall was unaffected, speed was.
>
> #### What I deliberately did NOT do, and why
> Tagged nothing and skipped FP-2/FP-4/FP-6, REC-5 and API-6/API-7b: the owner questions below
> went unanswered (asked 2026-10-30, no reply in 5 min), and each is public, trades recall, or
> breaks the API.
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
of the triggers is still read once. Stages today: JSON escapes → HTML references → percent (≤3
rounds) → fold.

No open items. Known edge kept on purpose: a Windows path `C:\temp\nancy@…` masks `ancy@…`
(the `\n` reads as an escape); see README.

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

- ⬜ **REC-5** Medicare MBI as a new type — `MBI: 1EG4-TE5-MK73` missed. Dashed form anywhere, undashed
  only after `MBI`/`Medicare`, per-position validator; trap an uppercase 11-char request ID.

## §4 Robustness & API (API)

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

`bench_test.go` holds the benchmarks. After PERF-1 (`22c38af`, Apple M5, clean / dirty / one `%20`):
1 KB log 270 / 251 / 304 µs; 100 KB JSON 11.0 / 33.9 / 22.8 ms; 1 MB prose 105 / 304 / 213 ms. Dirty
text gains least: its cue words are present, so their recognizers run. Profile is almost all `regexp`.

- ⬜ **PERF-2** One `%20` or NBSP still costs a second full read (1 MB clean 105 → 213 ms) — rescan
  bounded windows around decoded/folded bytes instead.

## §6 Measurement (MEAS)

Corpus at `8b02d83`: 81 entries, 113 floor values, 3 Presidio-only, 49 traps; coverage 94.9%.

- ⬜ **MEAS-3** Corpus shapes — entries are short (median 66 chars), 4 multi-line, 1 code, 0 real table
  rows. Add a structured log line, a CSV row under its header, a multi-paragraph clinical note with
  visit-date traps, a code snippet with hex constants; optional `shape`/`targets` fields.
- ⬜ **MEAS-4** Port parity — TODO.md's "55 of 55" (ask-meadowlark port) was scored at `d04df64` on a
  56-entry corpus; it is stale at 81. Optional per-entry JSON results flag so the port can diff.

## §7 Release (REL)

- ⬜ **REL-1** Cut `v0.1.2` — exported API unchanged since `v0.1.1`; Unreleased fixes a Chain panic,
  the zero-`Timeout` Presidio bug, quadratic `Mask`, per-call regex compile. Tagging is public:
  owner's call, §8.
- ⬜ **REL-2** README states cost per KB for request-path users (numbers in §5).

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
