# B1693 — SAFETY-comment audit, kernel core crates

Scope audited: `crates/kernel/{syscalls,kmain,mm-pmm,sched,fs,pci-boot}`,
`crates/arch/*`, `crates/shared/kalloc`. 147 `code/safety-{missing,short}`
findings in scope on `origin/main`; 0 after this branch. Every block was read
before its comment was written; the comment names the lock, the ordering, or
the single-mutator rule a reviewer must check, not the code.

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| FIXED B1693 | med | autofs dev-ioctl accessed the user parameter block through `*mut u32` / `*mut u64` after validating it with `align=1`, so a caller passing a misaligned pointer produced unaligned accesses Rust does not define, and a field write that faulted was ignored rather than reported | `syscalls/src/016_ioctl/autofs.rs` — 13 raw `read_volatile`/`write_volatile` sites; `userbuf::validate_user_buf(ptr, len, 1)` performs no alignment check when `align <= 1`. Now `uaccess::copy_{from,to}_user` (byte-wise, fault-fixed) and each field access returns EFAULT on failure. The file now contains zero `unsafe` blocks. | B1693 |
| FIXED B1693 | low | `sched_yield` and `futex` debug stack-walkers dereferenced user stack slots and a futex word with `read_volatile`, taking a kernel fault on an unmapped slot instead of failing the read | `syscalls/src/024_sched_yield.rs` (2 sites, `debug-syscall`), `syscalls/src/202_futex.rs` (2 sites, `debug-ustack`). Both now `uaccess::copy_from_user`, breaking the walk on the first unreadable slot. Diagnostic-feature-gated, so not reachable in a shipped build — recorded because the class is the same as the autofs row. | B1693 |
| OPEN | low | `spec-lint`'s `code/safety-*` rule only scans the 4 lines immediately preceding `unsafe {`, so a block whose SAFETY marker heads a longer comment, or is separated from the block by one declaration, reports as `safety-missing` even though it carries a full audited rationale | `tools/spec-lint/src/code_lint.rs:298` `for back in 1..=4`. 12 of the 147 in-scope findings were this false positive (e.g. `hal-x86_64/src/context.rs` context-switch clobber rationale, 1165 chars). Worked around here by making the SAFETY statement the last line before each block; the linter itself is another lane's file and was not changed. | unassigned |
| OPEN | low | `fs` test `pollout_tracks_current_pipe_capacity` fails on `origin/main`, unrelated to this branch | `cargo test -p fs --test sys_pipe2_shape` in the clean main tree at `cabbbf0aa`: `left: Ok(4096), right: Ok(2)` at `crates/kernel/fs/tests/sys_pipe2_shape.rs:210`. Pre-existing; this branch touches no pipe code. | unassigned |
| NOTE | info | `mm-pmm` `debug-fwm` / `debug-mount` diagnostics read a user VA through the HHDM alias of a present leaf rather than through `uaccess`; sound because the leaf is read out of the live root first, but it is the same shape as the two rows above and would break if a caller ever passed an address whose page could be reclaimed mid-read | `mm-pmm/src/user_as/debug.rs` `dump_u64_at` + the WATCH_VA read. Both are single-feature debug hooks with a fixed 8/16-byte read at a known page offset; documented in place rather than rewritten. | unassigned |

No unsound block was found in `sched`'s raw-`Arc` machinery (`switch.rs`,
`ttwu.rs`, `kthread.rs`, `sigpend.rs`): every `current_ref` borrow audited
here is published by `swap_current` and held under preempt-off, so the
runqueue's own Arc outlives it. No `glue_mmap(..., phys_base=Some(pa), ...)`
on refcounted RAM was found in scope.
