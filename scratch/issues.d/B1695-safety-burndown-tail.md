# B1695 — `code/safety-*` burndown tail

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | low | `crates/kernel/net` still holds the last 3 `code/safety-missing` findings (`rtnl.rs:35`, `sock_io.rs:220`, `unix_sock/listener.rs:309`). Not taken by this lane: several `net` lanes were active concurrently and a parallel edit there would conflict. | `cargo run -q -p spec-lint \| grep code/safety-` → 3 rows, all under `crates/kernel/net`. Repo-wide count was 16 before this PR. | unclaimed |
| INFO | info | Audit result: all 13 blocks this lane documented are **sound**. No unsound `unsafe` was found, so no bug row is filed. Each rests on a named invariant — see below. | Per-site prose in the diff; both arches build, `cargo test` green on every touched crate. | B1695 |
| INFO | info | `drv-ps2-keyboard/src/lib.rs` was 498 lines, 2 under the 500 split cutoff — adding SAFETY prose crossed it. Split into `lib.rs` (manifest) + `noop.rs` + `imp/{mod,regs,state,ports,bringup,irq,driver}.rs` in this PR rather than deferring. Largest resulting file is 169 lines. | `wc -l crates/drivers/drv-ps2-keyboard/src/**/*.rs` | B1695 |
| INFO | info | The `vt` hook indirection (`SIGNAL_HOOK`/`OWNER_ALIVE`/`ON_SWITCH` as `AtomicPtr<()>` + `transmute` back to a `fn`) is sound but type-unchecked by construction: soundness rests entirely on every store going through the typed `set_*_hook` setter. An `AtomicPtr` of the concrete `fn` type, or a `Spinlock<Option<fn(..)>>` as `cgroup::state` already uses, would make it checked. Not changed here — this lane is comment-only for `vt`. | `crates/drivers/vt/src/state.rs` `fire_signal` / `owner_alive` / `fire_switch`; contrast `crates/kernel/cgroup/src/state.rs:15`. | unclaimed |
| INFO | info | spec-lint's `safety-missing` check only looks at the line immediately preceding `unsafe {`. A correct SAFETY comment above a multi-line `let` binding whose `unsafe` lands on a later line still reports missing. Cost one edit round-trip here (`vt/src/state.rs` `owner_alive`, worked around with a local type alias to keep the block on one line). | Comment at `state.rs:85-87` with `unsafe` at `:88` reported `code/safety-missing`; collapsing the binding cleared it. | unclaimed |

## Invariants named (audit record)

| Site | Invariant that makes it sound |
|---|---|
| `security/bpf/token.rs:19` | `cur` is the running task; every writer of its `fd_table` slot (execve/unshare/close_range/exit) runs on the task itself, so no concurrent `replace_fd_table`. Matches the idiom already used across `security/src/bpf/`. |
| `firmware/acpi/iort.rs` `target_is_its_group` | `p` is the HHDM-mapped IORT base, `table_len` its SDT length; the guard proves `off + IORT_NODE_HEADER_BYTES <= table_len`, so the 1-byte node-type read is inside the table. |
| `arch-irq/lapic/dispatch.rs:253` | Same `PtRegs` frame the vector was read from — non-null (checked) and owned by this task's kernel stack until `oxide_irq_resume_user` pops it. |
| `ipc/futex/pi/exit.rs:66` | `read_word_for_exit` already proved the word in-range, 4-aligned and present+writable in the dying task's still-active address space. |
| `ipc/futex/wait.rs:149,168` | Single-mutator mm slot per `13§5`; `cur` is this CPU's running task, so no other CPU can replace its mm. |
| `mmio-map/lib.rs:126` | Forwarded contract — `map_owned` is `unsafe` so its caller carries `map_pages`' device-MMIO precondition; the returned `Mapping` takes sole ownership of the VA range. |
| `vt/state.rs` ×3 | The only non-null store to each `AtomicPtr` is the matching typed `set_*_hook`, so a non-null value is a live `'static` code address of exactly that signature; null returns early. |
| `drv-ps2-keyboard` `install_irq` drain | `PRESENT` and `IRQ_ENABLED` are both published and the redirection entry points at `irq1_handler` — the same state a real IRQ1 delivery runs under. |
| `drv-ps2-keyboard` `probe` ×2 | `install_irq`: `bringup` returned true, single-CPU bind window, nothing else touches the I/O APIC or 0x60/0x64. `bringdown`: `install_irq` unwound its own vector/pin before failing and never set `IRQ_ENABLED`, so no IRQ can be in flight. |
