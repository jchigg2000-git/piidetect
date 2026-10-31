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

> ### ▶ RESUME HERE — session handoff 2026-10-31
>
> **State:** `main` clean, CI green at `1b16ab4`; tagged `v0.2.0` 2026-10-31 (owner: *"yes to all
> four, tag v0.2.0 now"*). Round 4 open: FP-2/FP-4/FP-6 and the breaking API-6/API-7b batch, for `v0.3.0`.
>
> **▶ NEXT ACTION: round 4 — FP-2/FP-4/FP-6 (one builder, `regex.go`) ∥ API-6/API-7b (one builder).**
>
> #### What shipped
> Rounds 1–3, released as `v0.2.0` (see `CHANGELOG.md`).
>
> #### What I found by reading that nobody reported
> Nothing new since round 3.
>
> #### What I deliberately did NOT do, and why
> REC-5 (MBI) not started: the owner's yes covered the four questions; MBI was asked separately.
>
> #### Questions — each one line from you
> - REC-5: add Medicare MBI as a type?

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

- ⬜ **FP-2** Space-separated SSN without a label — `"GET /api HTTP/1.1" 200 12 4096` → `[SSN]`; `123+45+6789`
  after `+` folding (`regex.go:78`, `decode.go:100`). Fix: a spaced match needs an SSN label.
  Cost: `SSN on file 123 45 6789` missed. Approved 2026-10-31.
- ⬜ **FP-4** Space-only 3-3-4 phone shapes — `sizes 512 768 1024`, `dims 640 480 1920` → `[PHONE]`.
  Fix: spaces-only separators need a phone label (add `call`/`text` cues). Cost: `call me at 415 555
  0173` risky without them. Approved 2026-10-31.
- ⬜ **FP-6** Issuer prefixes — `ports 8080 8443 9090 3000` → `[CREDIT_CARD]` (Luhn passes). Reject
  leading 31–33, 7, 8 other than 81/82, 9 other than 9792 (`issuable`, `regex.go:538`). Cost: 7xxx
  fleet and other 9xxx national cards missed. Approved 2026-10-31.

## §3 Recall (REC)

Label-cued only; none of these widens an unlabelled shape.

- ⬜ **REC-5** Medicare MBI as a new type — `MBI: 1EG4-TE5-MK73` missed. Dashed form anywhere, undashed
  only after `MBI`/`Medicare`, per-position validator; trap an uppercase 11-char request ID.

## §4 Robustness & API (API)

- ⬜ **API-6** Error shape (breaking) — `Run`/`Redact` return `[]error` (`api.go:33`,
  `piidetect.go:130`); move to one `error` via `errors.Join` of `*DetectorError` + `ErrSpanOutOfRange`.
  Approved 2026-10-31; ships in `v0.3.0`.
- ⬜ **API-7b** Breaking cleanups for v0.2 — `Presidio.SetPatternPack` returns `error`; unexport
  `RuneToByteOffsets`; rename `WithPresidio`. Approved 2026-10-31; ships in `v0.3.0`.

### Parked ideas
- 💭 Streaming `io.Reader` with overlapping windows; walking JSON document values. Large; after v0.2.

## §5 Performance (PERF)

`bench_test.go` holds the benchmarks; README "What it costs" states them for users. After PERF-1
and PERF-2 (Apple M5, clean / dirty / one escape): 100 KB JSON 11 / 32 / 12 ms; 1 MB prose 117 /
324 / 124 ms. Dense text is the slow case: its cue words are present, so their recognizers run.

No open items.

## §6 Measurement (MEAS)

Corpus now: 169 floor values, 0 missed, 0 FP, 0 traps fired; per-type and per-shape tables in
`go test -v -run Corpus`; `PIIDETECT_CORPUS_RESULTS=path` writes per-entry JSON for the TypeScript
port. CI: Go 1.22 + stable, pinned staticcheck, coverage floor 90%.

No open items. 🔬 OWED — the ask-meadowlark port's parity claim (55/55 at `d04df64`) is stale; that
repo's session re-scores with the results file.

## §7 Release (REL)

No open items.

## §8 Open-decisions index

- ~~**REL-1** tag `v0.2.0` now, or after the breaking batch?~~ **CLOSED 2026-10-31 (owner):** tag `v0.2.0` now; breaking batch is `v0.3.0`.
- ~~**FP-2 / FP-4** label required for space-only SSN and phone shapes?~~ **CLOSED 2026-10-31 (owner):** yes.
- ~~**FP-6** tighter card issuer prefixes?~~ **CLOSED 2026-10-31 (owner):** yes.
- ~~**API-6 / API-7b** open v0.2 for breaking changes?~~ **CLOSED 2026-10-31 (owner):** yes, after the `v0.2.0` tag.
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
