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
> **State:** `main` clean, CI green at `918ae05`; tagged `v0.2.0` (`7c4dbca`) and `v0.3.0` 2026-10-31
> (owner: *"sure"*, to tagging `v0.3.0` and to MBI). Go floor 1.26; actions SHA-pinned; govulncheck in CI.
>
> **▶ NEXT ACTION: none queued — every survey item has shipped; parked: streaming `io.Reader`, JSON value walking (§4).**
>
> #### What shipped
> REC-5: `MBI` type (`TypeMBI`) — dashed uppercase anywhere, undashed or lowercase only after an
> MBI/Medicare label; per-position validator; corpus 176 values, 0 missed, 0 FP. Unreleased.
> Round 4: FP-2/FP-4 spaced SSN and phone shapes need a label (`call`/`text` added as phone cues);
> FP-6 card issuers 31–33, 7, 8 (not 81/82), 9 (not 9792) rejected; API-6 one `error` from
> `Run`/`Redact`/`RedactWith` via `errors.Join` of `*DetectorError`, `ErrSpanOutOfRange`; API-7b
> `Presidio.SetPatternPack` returns `error`, `RuneToByteOffsets` unexported, `WithPresidio` →
> `NewWithPresidio`. Corpus 171 values, 0 missed, 0 FP, 0 traps fired.
>
> #### What I found by reading that nobody reported
> `Presidio.SetPatternPack` now rejects empty deny lists and zero thresholds that were skipped
> silently before; a chain forwarding such a pack fails every `Run` until it is fixed (fail closed).
>
> #### What I deliberately did NOT do, and why
> Nothing held back.
>
> #### Questions — each one line from you
> - None open.

---

## §1 Encodings (ENC)

The decode pass (`decode.go`) reads text twice — as given and normalized — and maps spans back.
Every stage added here must compose into `orig` the way `percentDecoded` does, and text with none
of the triggers is still read once. Stages today: JSON escapes → HTML references → percent (≤3
rounds) → fold.

No open items. Known edge kept on purpose: a Windows path `C:\temp\nancy@…` masks `ancy@…`
(the `\n` reads as an escape); see README.

## §2 Precision (FP)

Each fix only removes claims and ships with its trap entry in `seed.json`.

No open items.

## §3 Recall (REC)

Label-cued only; none of these widens an unlabelled shape.

No open items.

## §4 Robustness & API (API)

No open items.

### Parked ideas
- 💭 Streaming `io.Reader` with overlapping windows; walking JSON document values. Large; after v0.2.

## §5 Performance (PERF)

`bench_test.go` holds the benchmarks; README "What it costs" states them for users. After PERF-1
and PERF-2 (Apple M5, clean / dirty / one escape): 100 KB JSON 11 / 32 / 12 ms; 1 MB prose 117 /
324 / 124 ms. Dense text is the slow case: its cue words are present, so their recognizers run.

No open items.

## §6 Measurement (MEAS)

Corpus now: 176 floor values, 0 missed, 0 FP, 0 traps fired; per-type and per-shape tables in
`go test -v -run Corpus`; `PIIDETECT_CORPUS_RESULTS=path` writes per-entry JSON for the TypeScript
port. CI: Go 1.26 + stable, actions pinned by SHA, pinned staticcheck and govulncheck (stable leg),
coverage floor 90%.

No open items. 🔬 OWED — the ask-meadowlark port's parity claim (55/55 at `d04df64`) is stale; that
repo's session re-scores with the results file.

## §7 Release (REL)

No open items.

## §8 Open-decisions index

- ~~**REL-1** tag `v0.2.0` now, or after the breaking batch?~~ **CLOSED 2026-10-31 (owner):** tag `v0.2.0` now; breaking batch is `v0.3.0`.
- ~~**FP-2 / FP-4** label required for space-only SSN and phone shapes?~~ **CLOSED 2026-10-31 (owner):** yes.
- ~~**FP-6** tighter card issuer prefixes?~~ **CLOSED 2026-10-31 (owner):** yes.
- ~~**API-6 / API-7b** open v0.2 for breaking changes?~~ **CLOSED 2026-10-31 (owner):** yes, after the `v0.2.0` tag.
- ~~**REC-5** add MBI as a type?~~ **CLOSED 2026-10-31 (owner):** yes.
- ~~**v0.3.0** tag now that the breaking batch is on main?~~ **CLOSED 2026-10-31 (owner):** yes, tagged.
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
