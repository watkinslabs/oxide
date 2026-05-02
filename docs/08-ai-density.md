# 08 AI-Density

FROZEN 2026-05-02. Dep:`02`.

Audience=AI. Optimize tokens. Never lose capability/invariant/test/constraint. Compress prose only.

## 1 Doc rules

1. Drop: articles ("the/a/an") unless parse-required, transitional prose ("note","also","in addition","this is","we will"), section-title repeats in body, motivation paragraphs, restating prior sections.
2. Drop: examples for things a type+name already specifies. Keep: examples that pin a corner-case invariant.
3. Headers: number only. `## 3` not `## 3. Foo`. Exception: charter docs (`00`–`09`) keep titles for routing.
4. One-line bullets. No multi-sentence bullets unless the second sentence carries an invariant the first doesn't.
5. Tables > lists > sentences. Schemas (`field: type — meaning`) > prose definitions.
6. Cite by `<doc>§<n>`. Never restate.
7. Doc-comment markers (`# C:` `# Lk:` `# Ctx:` `# Sleeps:` `# Lin:` `# SAFETY:` `# Pre:` `# Post:`) per `09§6`. No prose substitutes.
8. No closing summaries. Doc ends with last numbered section (typically Open Questions).
9. No "Why X over Y" prose unless it's load-bearing on a frozen invariant. Otherwise → 1-line OQ entry.
10. Test contract: bullet lines, no per-item headings, no reasons (the test IS the reason).
11. Type-list sections: schema table, not Rust block, when fields are simple. Rust block only when traits/lifetimes/generics matter.
12. No "Notes:" or "Important:" prefixes; the line itself carries the weight.
13. Drop synonyms+qualifiers ("simply","just","really","actually","very","extremely","quite","rather","fairly","somewhat","essentially","basically","fundamentally").
14. Density target: ≤60% of lines are full sentences; ≥40% are tables/schemas/lists/code.
15. If a paragraph is 3+ sentences and not a worked corner-case, split into bullets or table.

## 2 Code rules

1. Zero comments unless the comment encodes invariant the type+name can't. SAFETY, Pre, Post, Complexity-on-`pub fn` markers (per `09§6`) excepted.
2. No "what" comments. No "obviously" comments. No code-restating comments.
3. Names: short within scope (`pfn`,`pa`,`va`,`sb`,`ino`,`tid`) per `09`. Long only at module/crate boundaries where context is lost.
4. No redundant trait method docs (`/// Returns the foo.` on `fn foo() -> Foo` is a build error via lint).
5. Use `?` over `match Err(e) => return Err(e)`. Never expand for "clarity."
6. No inferred numeric/address/layout/ABI/MMIO/unsafe-adjacent local types; constructor-named concrete types may omit annotation.
7. No method chains broken into named locals unless the local is reused.
8. Group `use` minimally; one line per crate where reasonable.
9. No defensive code at internal boundaries (only at user/device/network ingress).
10. Constants inline at use-site if used once, named at module level if reused.
11. Newtypes: `#[repr(transparent)] pub struct Pfn(pub u64);` — no doc-comment unless invariant beyond name.
12. Tests: assertion-dense, setup minimal, no per-test docstrings, table-driven where applicable.

## 3 Stays full-fidelity

Frozen invariants — every one fully specified.
ABI tables — numeric values explicit.
SAFETY comments — must name invariant ≥30 chars (lint).
Test contract pass criteria — concrete numbers.
Open Questions — only place reasoning earns its tokens.
Capability tables (`15§2`,`41§3`) — no abbreviation that loses a number or a status.

## 4 Negative examples (forbidden)

- "This document defines..." → drop, replace with "Defines:" if needed at all.
- "Note that the page-cache..." → drop "Note that".
- "## 5. Inputs / Outputs / Dependencies" with then a paragraph saying "this section lists...".
- `pub fn foo(&self) -> KR<()>;\n/// Frees the resource.` → comment dies; name carries.
- `impl X { /// Constructs a new X.\n pub fn new() -> Self }` → comment dies.
- "We chose CFS because it is well-understood" in body → if load-bearing, → frozen invariant; else → OQ line.
- "In this section, we will..." → drop entirely.

## 5 Compression of existing docs

Big-O argument: docs re-read N times across project life; every token paid N×. Compression always wins.

Sweep in progress 2026-05-02: every doc passed once under §1+§2. Order: most-cited first (`01`,`06`,`02`,`03`,`04`,`07`,`05`,`00`,`09`,`38`,`14`,`15`,...). Each rewrite preserves every invariant, table, test criterion, OQ; only prose dies.

Post-sweep rule: future revisions stay dense. Lint (§6) catches drift.

## 6 Lint enforcement

`tools/spec-lint/` checks:
- DRAFT/FROZEN line present.
- `## N` headers numbered correctly.
- No `## N. Title` outside `00`–`09`.
- Sections ≥3 paragraphs flagged for review.
- Forbidden phrases (§4) grep-failed.
- `pub fn` doc-comment is only the markers from `09§6`.
- `unsafe {` followed by `// SAFETY:` line ≥30 chars.

