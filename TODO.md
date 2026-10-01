# TODO

Notes left here from other repos' sessions. This repo's own session decides what to do with each.
Done and removed (2026-10-01): MRN two-character separator, Unicode spaces after a label, the
four-consecutive-years card false positive, a date glued to its birth cue, and the plural DOB
cues; see CHANGELOG Unreleased.

## 2026-09-27 — from ask-meadowlark: its port of the floor, synced to v0.1.1 and d04df64

ask-meadowlark carries a TypeScript port of this floor (`packages/engine/src/redact/floor.ts` in
that repo). On 2026-09-27 it adopted every fix in v0.1.1 and in the Unreleased section of
`CHANGELOG.md` (4f3bf23, d04df64) that applies to it. Scored the way `TestRegexCorpusFloors`
scores, on this repo's corpus at d04df64, the port now catches 55 of 55 values whole with 0 traps
fired and 0 unmarked claims (it was 22 of 55 with 8 traps before). *(Corrected later on
2026-09-27, see the last entry: 55 of 55 with 8 traps fired, the same 8 as before, on purpose.)*
What it does differently, so the two stay honest about each other:

- **Uncued `MM/DD/YYYY` DOB: removed there, kept here.** In a reporting tool that shape is a
  period bound ("between 01/01/2026 and 06/30/2026" became "between [DOB] and [DOB]"), so the port
  claims every date shape only after a birth cue. No change suggested here; recorded because a
  caller reading both would otherwise assume parity.
- **Added later on 2026-09-27, after a cold review of the port: where this floor is narrower than
  the port's old one, the port kept the old masking.** Each is a value this floor sends:
  - *A bare line break between a label and its value*, a pasted form field: "Why was MRN\n4481920
    denied?", "DOB\n1985-03-14", "born\n03/14/1985". This floor crosses a line break only after an
    explicit separator, to avoid the header-row traps. The port crosses a bare break too, unless
    the label follows a column gap on its line (a tab, or two or more spaces, with something before
    it: "Name   MRN"), so both header-row traps still pass there (55 of 55, 0 traps). Suggested the
    same here, with corpus entries for "Why was MRN\n4481920" and "DOB\n1985-03-14". *(Withdrawn
    later on 2026-09-27, see the last entry: the column-gap exception is unsafe.)*
- **DOB cue words.** The port also takes "birth day(s)", a run of spaces in "born  on", and a
  comma between cue and date. Low value; listed for parity. A comma is left out here on purpose:
  "since birth, 3/20/2024" would claim a visit date.
- **ZIP.** The port has an anchored ZIP recognizer (a case-sensitive state abbreviation, a ZIP or
  postal-code cue, or the ZIP+4 shape); this floor has none. Nothing suggested.
- **A span outside the text.** This chain drops it and reports the detector's error; the port's
  caller turns that error into a refusal of the question (fail closed). Not a library divergence,
  noted so the two readings of "reported" are not confused.

## 2026-09-27 (later) — from ask-meadowlark: the port masks upstream's header-row traps and six more, on purpose

A second cold review of the port found that the column-gap exception above (a label after a tab
or two or more spaces on its line does not cross a bare line break) is far wider than a table
header: a double-spaced sentence ("Following up on the denial.  MRN\n4481920 — …"), a numbered
or bulleted list ("1.  MRN\n4481920", "•\tMRN\n4481920"), a padded pasted form ("Patient: Jane
Doe    MRN\n4481920") and "Client seen twice.  DOB\n03/14/1985" all have its shape, and it sent
the MRN or birth date in 18 of the reviewer's 20 such wordings. The same holds for this floor,
which crosses no bare break at all: it sends every one of them. So the suggestion above to adopt
the column-gap rule here is withdrawn.

The port's rule is now that it never masks less than its own floor did before the sync, on any
wording. Where this floor added a rejection to cut a false positive, the port applies it only to
what this floor's wider patterns add, and keeps its old masking everywhere else. So on this repo's
corpus at d04df64 the port catches 55 of 55 values whole and fires 8 traps, on purpose, the same 8
its old floor fired: `trap_mrn_header_row`, `trap_dob_header_row`, `trap_phone_digit_run`,
`trap_oid`, `trap_epoch_millis`, `trap_nanp_placeholder` and both values of
`trap_ssn_never_issued`. 0 unmarked claims. A divergence, recorded here and in the port's floor
header; nothing suggested for this repo beyond the note above that its bare-line-break rule sends
a pasted form field's value.
