# 02 Spec Discipline

FROZEN 2026-05-02. Dep:none. Umbrella for all specs.

Specs are contracts. Spec wins; code follows. Spec is the durable artifact.

## 1 Lifecycle

`DRAFT —(checks)→ FROZEN —(body edit + revise: commit)→ FROZEN'`

DRAFT: mutable, no changelog discipline, code may not be written for the subsystem, OQ at bottom is sole ambiguity site.

Freeze gate (all required):
1. Zero open questions; every section in §4 template populated.
2. All cross-refs resolve via `tools/spec-lint/ xref` (target need not be FROZEN; section must exist).
3. Test contract concrete (numbers, oracles, coverage gates) where the spec describes a subsystem with executable behavior. Charter / meta specs (this one, `08`, `09`) exempt. PR-time gates pass.
4. Top-line `Status: FROZEN <date>`; commit `freeze: <spec>` on `Z<NN>-<spec>` branch.

Post-freeze change: edit the body so it states current truth. No in-file revision/changelog block — the record is the git commit + PR, which hold what changed, why, affected code, and test-contract impact. A spec reader must not have to read superseded history before the content.

Commit `revise: <spec> — <one-line>` on an `R<NN>-<spec>` branch; the commit body carries the rationale. Superseded text is deleted, not annotated.

## 2 Section types

Frozen: invariants, public ifc, ABI, on-disk fmt, complexity, test contract. Change requires a named reason in the `revise:` commit ("we changed our mind" ≠ reason; "violates `06§X`" = reason).

Negotiable: tuning constants, internal algo choices, debug instr, log strings. Edit ⇒ Changelog line, same commit.

OQ (DRAFT only): deferred decisions inside the same spec text. Either become a numbered section or get answered before freeze. Never silently disappear; never move to a v2 doc (there is no v2).

## 3 Drift handling

Code finds spec wrong:
- Misread spec → fix code.
- Real bug/omission → stop. Add OQ (DRAFT) or revise the body (FROZEN). Resolve. Then code.
- Inconvenient spec → revise or follow. Never deviate "just here."

## 4 Spec template

```
# NN <Subsystem>
DRAFT|FROZEN <date>. Dep:`a`,`b`. Provides:`c`,`d`.

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

## 5 Cross-deps + freeze order

`Dep:` line on every spec lists docs whose content this one cross-references. Cross-references may cycle (HAL ↔ IRQ ↔ timer); `tools/spec-lint xref` enforces that every reference resolves, regardless of cycle.

Freeze order (linearization of the spec graph for freezing purposes) lives in `docs/MANIFEST.md§Freeze order`. Charters first, then subsystem leaves, then HAL, then mid-tier, then upper. A spec may freeze when its position in that order is reached, regardless of whether one of its cross-referenced docs is still DRAFT — provided no behavior in this spec changes if that DRAFT changes (i.e., the cross-reference is informational, not load-bearing).

Co-frozen group: when N specs cross-reference each other in a cycle (HAL/IRQ/timer is the canonical case), freeze them in one PR. Listed in MANIFEST§Freeze order as a single batch.

Editing a frozen spec marks downstream dependents `REVIEW` in MANIFEST; dependents re-read and confirm-or-flag.

## 6 MANIFEST

`docs/MANIFEST.md` = authoritative index. Per-spec row: file, status, frozen-date, deps. Same-commit update on status change. Verification: `tools/spec-lint/` (`docs|code|manifest|xref|all`) checks file-vs-MANIFEST presence diff, status mismatch, status-line form, header form, forbidden phrases, cross-ref resolution.

## 7 Pre-freeze re-read (no duration gate)

Before flipping a spec to FROZEN, re-read top-to-bottom with no context except the page; deliberately try to break each invariant; mentally implement §4 ifc against §3 invariants. No clock; no soak; correctness is the gate.

## 8 Not this

- Spec a 50-line helper. Skip.
- 5000-word slab spec. Over-design.
- Freeze on learning. Revisions are first-class; git holds them.
- Substitute for tests. Frozen + no test contract = wish.

## 9 Standing rules (frozen)

1. No code against DRAFT spec.
2. Frozen sections change only via a body edit whose `revise:` commit names the rationale. No in-file revision blocks; git is the change record.
3. OQ are sole ambiguity site; absent in FROZEN.
4. Drift → revise spec → code. Never reverse.
5. No duration-gated waits at any layer (no cool-off, no soak, no 24h/48h/168h gates). Correctness is the gate, not the clock.
6. MANIFEST authoritative; `tools/spec-lint/` enforces.
7. Cross-deps acyclic, listed in §2 of every spec.
8. No v2. Every spec describes the full Linux-equivalent surface. "Deferred to v2", "rides v2.x", "v2.x deferrals" sections forbidden.
9. Freeze branch form `Z<NN>-<spec>`; revise branch form `R<NN>-<spec>` (per `CLAUDE.md§Git workflow`).

## 10 Changelog

(none)
