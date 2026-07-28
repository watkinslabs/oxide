# PARTIAL-row triage — what is actually missing vs merely untested

**SUPERSEDED 2026-07-28 by `scratch/partial-surface-2026-07-28.md`** — this file predates the four subsystem audits and ~30 merged fix lanes; several entries are verified stale (`rseq`, `personality`, `RLIMIT_MEMLOCK`, lease break). Kept for history. Use the successor.

Status: LIVE 2026-07-27. Source: `scratch/syscall-compliance-matrix.md` (386 rows).
Sibling ledgers: `scratch/wait-diff-open-items.md` (W1-W7).

`PARTIAL` currently covers two very different things. This splits them so the
remaining debt can be worked by owner instead of by row number.

| Class | Rows | Meaning |
|---|---|---|
| A — functional gap | 33 | named behaviour Linux has and oxide does not |
| B — coverage debt | 153 | behaviour believed correct, audit/harness incomplete |

Class B is not a lie on the row; it is an un-finished proof. Class A is the real
outstanding surface. Only class A is enumerated here.

## A1 — blocks or degrades a GNOME desktop

| Item | Gap | Owner subsystem | Row |
|---|---|---|---|
| RT scheduling | `SCHED_RR` stored and picked as RT but has NO round-robin quantum — no tick requeue exists in `crates/kernel/sched`, so RR runs identically to FIFO. `SCHED_DEADLINE` has no class at all and is refused. | sched | `sched_setscheduler`, `sched_rr_get_interval` |
| Controlling-tty teardown | `disassociate_ctty(1)` not implemented — a session leader's final exit neither vhangs up its session nor `SIGHUP`s the tty foreground pgrp (`drivers/tty/tty_jobctrl.c`). | tty + sched | `exit` |
| `ctty` ownership | `ctty` lives on the task, not the `ThreadGroup`; moving it touches console routing, `tty_ioctl`, `openat /dev/tty`, clone. | tty | `setsid` |
| rseq critical sections | `sched::rseq` has no `rseq_cs` / IP-fixup, so no critical section can be restarted; `MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ` is consequently refused. | sched | `membarrier` |

`rtkit`, `pipewire` and `gnome-shell` all request RT policy; RR-without-quantum
means one RT thread can hold a CPU against its peers indefinitely. That is the
single highest-value class-A item.

## A2 — security surface

| Item | Gap | Owner | Row |
|---|---|---|---|
| ASLR | No ASLR exists at all (`docs/31§6`), so `ADDR_NO_RANDOMIZE` is a no-op and `PER_CLEAR_ON_SETID` has no execve secure-exec path to hook. | elf-loader + vmm | `personality` |
| `i_writecount` | No `i_writecount` / `deny_write_access` anywhere, so `ETXTBSY` on truncating a running executable is impossible. | vfs + exec | `truncate`, `ftruncate` |
| mount-ns re-root | `commit_nsset`'s `set_fs_root`/`set_fs_pwd` has no counterpart — entering a mount namespace leaves cwd/root on the old tree. | mount | `setns` |
| `F_SEAL_EXEC` | Missing from `F_ADD_SEALS`' valid mask and from tmpfs `setattr` enforcement; no `vm.memfd_noexec` sysctl node. | vfs/tmpfs | `memfd_create` |
| key upcall | No `/sbin/request-key` helper, so a miss is always `ENOKEY` and a key can never be constructed on demand. | keys | `request_key` |

## A3 — correctness, lower blast radius

| Item | Gap | Owner | Row |
|---|---|---|---|
| lease break | `F_SETLEASE` registers a lease but there is no blocking lease break. | vfs | `fcntl` |
| `s_wb_err` | No per-superblock errseq latch, so a writeback error between open and call is not reported as `errseq_check_and_advance` would. | vfs | `syncfs` |
| `fdatasync` | Missing the timestamp-only-writeback elision that distinguishes it from `fsync`. | vfs | `fdatasync` |
| `fadvise64` | `WILLNEED` populates synchronously where Linux submits async readahead; `NOREUSE` carries no reclaim bias (LRU has no folio-activation hook). | vmm | `fadvise64` |
| rlimits | `CPU`/`CORE`/`NPROC`/`MEMLOCK`/`AS`/`SIGPENDING`/`MSGQUEUE`/`RTTIME` are stored but not enforced; each belongs to the lane owning its enforcement point. `RSS`/`LOCKS` are no-ops in upstream Linux too and are NOT gaps. | many | `getrlimit`, `setrlimit` |
| userfaultfd | Only the MISSING mode is wired. | vmm | `userfaultfd` |
| aarch64 vDSO | `crates/kernel/syscalls/vdso/vdso-aarch64.so` absent, blocking the aarch64 syscalls target check. | build | `ioctl` |

## A4 — unexecuted paths (implemented, never run)

SysV blocking has never executed: `basic.target` boot does not exercise it and no
hosted test can, because hosted builds have no `mm`.

| Row | Unexecuted path |
|---|---|
| `semop` | sleeping path |
| `msgsnd`, `msgrcv` | sleeping path |
| `shmdt` | address-space half (`snapshot_vmas` + `munmap`) |

These are the natural next additions to the `wait_diff` guest differential
(`userspace/wait_diff/`), which already runs 42 records against real Linux on
both arches — it is the only harness in-tree that can execute them.

## Ordering

1. RT scheduling (A1) — largest desktop impact, self-contained in `crates/kernel/sched`.
2. Controlling-tty teardown + `ctty` on `ThreadGroup` (A1) — one tty lane, two rows.
3. SysV blocking into `wait_diff` (A4) — cheap, reuses a working harness.
4. `i_writecount` (A2) — one primitive closes `ETXTBSY` on two rows.
5. ASLR (A2) — largest single piece of work here; own phase.
