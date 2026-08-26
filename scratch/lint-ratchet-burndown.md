# spec-lint ratchet burndown

The ratchet baseline was raised on 2026-08-26 (`C314`) with
`spec-lint ratchet --update --allow-growth`, a deliberate policy decision taken
because the gate had been failing on `main` itself for fifteen days and every
lane was passing `SKIP_LINT_RATCHET=1` to push — which disarmed the check for
findings a branch *did* introduce, not just the inherited ones. Raising the
floor restores that: a new finding fails the gate again, today.

The 981 findings the raise absorbed are **not forgiven**. They are this
document. The baseline may only shrink from here, so every row below is burned
down by fixing findings and re-running `make lint-ratchet-update`, never by
raising a count again.

## How it broke

Bisected against `origin/main`, sampling `spec-lint ratchet` per commit:

| commit | date | verdict | findings / keys |
|---|---|---|---|
| `bff1c360a` | 2026-08-10 | **PASS** | 1702 / 76 (exactly at baseline) |
| `6a8dfb0e3` | 2026-08-11 | **PASS** | 1702 / 76 |
| `915997bb5` | 2026-08-11 | **FAIL** | 1705 / 77 |
| `8ba1dcf0b` | 2026-08-13 | FAIL | 2081 / 100 |
| `d7d750f11` | 2026-08-22 | FAIL | 2042 / 112 |
| `main` | 2026-08-26 | FAIL | 2690 / 155 |

`915997bb5` is the merge of PR #5005 (`F867-ps2-aux-mouse`), an ordinary feature
PR that added three findings in one new key and was merged past the gate. Every
lane after it found the gate already red and bypassed it too; fifteen days of
that compounded to 981 findings above the baseline across 114 keys.

Two things this history establishes, both worth keeping:

- **A red shared gate does not stay a small problem.** The cost of the first
  bypass was three findings. The cost fifteen days later was 981.
- **`--update` alone could never have recovered it.** It writes
  `min(current, baseline)` per key, so it can only lower a count. The 2026-08-22
  baseline commit was itself written while the gate was red, which is why the
  file claimed counts the tree had not met since 2026-08-10.

## Burndown

One rule per lane, largest first inside a rule. `Status` is `OPEN`,
`IN-PROGRESS <branch>`, or `DONE <branch>`. Tighten the baseline in the same PR
that fixes the findings — slack below the baseline fails the gate, which is the
point.

| Status | Rule | Findings | Keys | Largest units | Branch |
|---|---|---|---|---|---|
| OPEN | `text/external-source-citation` | 57 | 2 | `scratch` +56, `crates/kernel/vfs` +1 | |
| OPEN | `doc/forbidden` | 9 | 1 | `docs` +9 | |
| OPEN | `doc/status` | 2 | 1 | `docs` +2 | |
| OPEN | `xref/doc` | 1 | 1 | `docs` +1 | |
| OPEN | `code/panic-fmt` | 3 | 2 | `crates/shared/kalloc` +2, `crates/kernel/syscalls` +1 | |
| OPEN | `code/safety-short` | 7 | 1 | `crates/shared/kalloc` +7 | |
| OPEN | `code/safety-missing` | 121 | 16 | `crates/kernel/mm-pmm` +23, `crates/arch/hal-x86_64` +16, `crates/arch/hal-aarch64` +15, `crates/arch/hal` +13, +12 more | |
| OPEN | `code/klog-ungated` | 208 | 16 | `crates/kernel/sched` +60, `crates/kernel/mm-pmm` +34, `crates/kernel/syscalls` +22, `crates/kernel/kmain` +17, +12 more | |
| OPEN | `code/pub-fn-complexity` | 573 | 74 | `crates/kernel/modules` +59, `crates/kernel/syscalls` +52, `crates/kernel/net` +43, `crates/drivers/drv-e1000` +38, +70 more | |
Total: **981 findings across 114 keys.**

The four text and doc rules at the top are editorial, carry no code risk, and
`text/external-source-citation` is a CLAUDE.md hard rule in its own right — repo
text may not name or quote external implementation files. They are the first
lanes to take.

`code/pub-fn-complexity` is the bulk and the slowest: it is real decomposition of
production functions, so it burns down per-crate behind that crate's own tests,
never as a tree-wide sweep.
