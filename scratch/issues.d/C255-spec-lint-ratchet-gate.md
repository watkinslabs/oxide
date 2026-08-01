# C255-spec-lint-ratchet-gate

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | high | `make lint` fails on main with **2696** spec-lint findings, 2693 of them kernel-side. Every one is a CLAUDE.md hard rule: `code/pub-fn-complexity` 1223, `code/safety-missing` 649, `code/klog-ungated` 625, `code/panic-fmt` 113, `code/safety-short` 58, `code/extern-std` 18, `manifest/dangling` 2, `code/no-std` 2, `xref/sec` 1, `len/over-cap` 1. | `cargo run -p spec-lint` on `2ca827e72`; per-key snapshot committed as `tools/spec-lint/baseline.tsv`. Not fixed here — C255 only stops the growth. | C255 (ratchet), later lanes (backlog) |
| FIXED C255 | high | Nothing observed the number. The `spec-lint` CI job is gated on repo variable `OXIDE_RUN_SPEC_LINT == '1'` and does not run; `make ci` did include `lint`, which made `make ci` unconditionally red and therefore unread; the pre-push hook ran `hosted-gate` and `feature-gate` but no lint at all. Three gates, none of them looking. | `.github/workflows/pr.yml:16`; `Makefile` `ci:` target; `.githooks/pre-push`. Fixed by adding an **unconditional** `lint-ratchet` CI job, a `lint-ratchet` pre-push gate, and swapping `ci:`'s `lint` for `lint-ratchet` so the aggregate gate is green-and-meaningful instead of red-and-ignored. | C255 |
| OPEN | med | All 20 `code/extern-std` + `code/no-std` findings are **lint false positives**, not code defects — the opposite of what the count suggests. `code/extern-std` does not model `cfg`: 16 of 18 sites are inside a `#[cfg(test)] mod tests`, one is `#[cfg(not(target_os = "oxide-kernel"))]`, one is `#[cfg(all(test, not(target_os = ...)))]`. `code/no-std` has two: `crates/kernel/conformance` is a hosted-only `[dev-dependencies]` test harness that is std by design, and `crates/kernel/syscalls/src/054_setsockopt/main.rs` is a syscall *slot* module the lint mistook for a crate root because of its filename. Fix belongs in `spec-lint`, not in the kernel. | `cargo run -p spec-lint -- code \| grep -E 'extern-std\|no-std'`, then the enclosing attribute at each site: e.g. `crates/kernel/sched/src/pid.rs:10` is `#[cfg(test)]` over `mod tests;`; `crates/kernel/ext4/src/lib.rs:21` is `#[cfg(not(target_os = "oxide-kernel"))]`. | follow-up lane |
| FIXED C255 | med | `len/over-cap` is a documented CI-failing hard cap (`docs/08§7`) with exactly one violator, `crates/shared/kalloc/src/lib.rs` at 1202 lines, and no gate enforced it. C251 filed it as OPEN and could not act. It is now inside the ratchet, so the count can only go down. | `wc -l crates/shared/kalloc/src/lib.rs` = 1202; baseline row `crates/shared/kalloc len/over-cap 1`. Split itself is the follow-up lane's work. | follow-up lane |

## Positive control (C255 ratchet)

Injected into `crates/shared/kalloc/src/walkstat.rs` — a crate that already carries
15 `klog-ungated` + 11 `pub-fn-complexity` findings, so the test also proves a new
violation cannot hide behind an existing pile:

    pub fn pc_panic_fmt(n: usize) { if n == 0 { panic!("pc {}", n); } }
    pub fn pc_unsafe(p: *mut u8) { unsafe { core::ptr::write(p, 0); } }

RED (`rc=1`), three keys named:

    REGRESSION crates/shared/kalloc [code/panic-fmt] 2 > 1 (baseline)
    REGRESSION crates/shared/kalloc [code/pub-fn-complexity] 13 > 11 (baseline)
    REGRESSION crates/shared/kalloc [code/safety-missing] 2 > 1 (baseline)

`--update` with the same tree also refuses (`rc=1`, "REFUSED to raise"), leaving the
baseline file byte-identical. After `git checkout` of the file: `rc=0`, "PASS — at
baseline". Wall clock 0.79 s.
