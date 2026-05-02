# 02 Spec Discipline

DRAFT 2026-05-02. Dep:none. Umbrella for all specs.

Specs are contracts. Spec wins; code follows. Spec is the durable artifact.

## 1 Lifecycle

`DRAFT —(48h cool-off + checks)→ FROZEN —(revision block)→ FROZEN'`

DRAFT: mutable, no changelog discipline, code may not be written for the subsystem, OQ at bottom is sole ambiguity site.

Freeze gate (all required):
1. Zero open questions (each → section or `docs/v2/<spec>.md` deferred entry).
2. All cross-refs resolve to FROZEN sections.
3. Test contract concrete (numbers, oracles, coverage gates). PR-time gates pass on the implementation. Soak result not required (background diagnostic only).
4. 48h cool-off on the spec text (edit resets clock). Re-read fresh.
5. Top-line `Status: FROZEN <date>`; commit `freeze: <spec>`.

Post-freeze change: prepend revision block:
```
## Revision <date>
- Changed: §X.Y …
- Why: …
- Affected code: …
- Test contract change: …
```
Commit `revise: <spec> — <one-line>`. CI: any FROZEN file in diff requires same-commit revision block.

## 2 Section types

Frozen: invariants, public ifc, ABI, on-disk fmt, complexity, test contract. Change requires revision block + named reason ("we changed our mind" ≠ reason; "violates `06§X`" = reason).

Negotiable: tuning constants, internal algo choices, debug instr, log strings. Edit ⇒ Changelog line, same commit.

OQ (DRAFT only): deferred decisions; either become a section or move to `docs/v2/<spec>.md` with rationale. Never silently disappear.

## 3 Drift handling

Code finds spec wrong:
- Misread spec → fix code.
- Real bug/omission → stop. Add OQ (DRAFT) or Revision block (FROZEN). Resolve. Then code.
- Inconvenient spec → revise or follow. Never deviate "just here."

## 4 Spec template

```
# NN <Subsystem>
DRAFT|FROZEN <date>. Dep:`a`,`b`. Provides:`c`,`d`.
(revision blocks if FROZEN)

## 1 Purpose
## 2 Inputs/outputs/deps
## 3 Frozen invariants (numbered)
## 4 Public ifc
## 5..N Design
## N+1 Complexity contract
## N+2 Concurrency
## N+3 Debug
## N+4 Log
## N+5 Perf budget
## N+6 Test contract
## N+7 Failure modes
## N+8 Cross-spec
## N+9 Changelog
## N+10 OQ (DRAFT only)
```

Missing section ⇒ not freezeable.

## 5 Cross-deps

Acyclic. Every spec's §2 lists deps by file. A spec freezes only when all deps frozen. Editing a frozen spec marks downstream dependents `REVIEW` in MANIFEST; dependents re-read and confirm-or-flag.

## 6 MANIFEST

`docs/MANIFEST.md` = authoritative index. Per-spec row: file, status, frozen-date, deps. Same-commit update on status change. CI verifies file presence + Status-line match.

## 7 Cool-off (substitute for reviewer)

48h on spec text (edit resets). Then re-read top-to-bottom with no context except the page; deliberately try to break each invariant; mentally implement §4 ifc against §3 invariants. The annoyance is the discipline.

## 8 Not this

- Spec a 50-line helper. Skip.
- 5000-word slab spec. Over-design.
- Freeze on learning. Revisions are first-class; just visible.
- Substitute for tests. Frozen + no test contract = wish.

## 9 Standing rules (frozen)

1. No code against DRAFT spec.
2. Frozen sections change only via dated revision block + rationale.
3. OQ are sole ambiguity site; absent in FROZEN.
4. Drift → revise spec → code. Never reverse.
5. Cool-off 48h on text, not calendar.
6. MANIFEST authoritative; CI-verified.
7. Cross-deps acyclic, listed in §2 of every spec.

## 10 Changelog

(none)

## 11 OQ

- `tools/spec-lint/` enforce (status line, revision-block-on-frozen-edit, `# C:` on every pub fn)? Yes; build at first freeze.
- v2 divergence: branch `docs/v2/` or in-file v1/v2? Lean: branch.
