# piidetect

**`ROADMAP.md` is the SINGLE SOURCE OF TRUTH for execution** — what's left, what's next, and
every phase / acceptance criterion / decision, across all workstreams. On any handoff, **read it
first and follow only it as the plan.** There are deliberately **no other `*_PLAN`, handoff, or
decision-log docs** — they were consolidated into it (2026-10-30); never recreate them. Put new plan or status
content in `ROADMAP.md`. If any doc's status conflicts with ROADMAP, ROADMAP wins.

**ROADMAP.md holds only open work — closure is deletion.** A finished, verified item is deleted
in the closing edit, never marked ✅ and kept; git and `CHANGELOG.md` are the history layer. Do
not preserve, restore, or re-add closed items. `git log -S'<ID>' -- ROADMAP.md` recovers any
deleted item.

**Backlog items are not blockers.** No item under a `BACKLOG` / `PARKED` status gates any other
work unless it carries a `⛔ BLOCKS:` line quoting the owner's instruction from when it was
parked. Absent that line, it is non-blocking. Do not infer blocking from urgency or dependency
order.

Read order for a fresh session: this file → `ROADMAP.md`, then `README.md` and `CHANGELOG.md` on demand.

The roadmap sync gate is `githooks/pre-commit` (enable with `git config core.hooksPath githooks`);
`PIIDETECT_SKIP_ROADMAP_SYNC=1` skips it for a mid-unit commit.
