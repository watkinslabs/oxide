# Syscall Linux-compliance ledger

Audit 2026-07-07 (4-reviewer stub audit + dispatcher review). Goal: every routed
syscall = full Linux semantics per `docs/15`, `docs/03`. No fake-success, no
core-op refusal, no non-durable lie. Fix one row at a time: branch → implement →
hosted test proving Linux behavior → both-arch build → PR → merge → flip Status.

Dispatcher: single entry `oxide_syscall_dispatch`; legacy fallback removed (B630,
#2794). Routing near-complete — only `NR_LISTNS` (470) unrouted (row X1).

Status: TODO | WIP | DONE. Branch filled when claimed.

## P0 — security: sandbox does not survive fork (verified)

| ID | Syscall(s) | Status | Branch | Fix |
|----|-----------|--------|--------|-----|
| S1 | seccomp fork/exec inheritance | DONE | B631 #2795 | `spawn_user_thread_for_fork` (both arches) now clones parent `seccomp_filters` into child; execve never clears it. |
| S2 | landlock fork/exec inheritance | DONE | B631 #2795 | same site: child clones parent `landlock_chain`. |

## P0 — data corruption / false durability (verified)

| ID | Syscall(s) | Status | Branch | Fix |
|----|-----------|--------|--------|-----|
| D1 | pwritev / pwritev2 (296/328) | DONE | B632 #TBD | `296_pwritev.rs` now a positional write mirroring `preadv`: extracts pos_l/pos_h, writes each iovec at the running offset via `inode().write(off,buf)`, never touches `f_pos`. |
| D2 | sync(2) | DONE | B633 #TBD | new `162_sync.rs sys_sync`: iterate `all_mounts()`, dedup superblocks by Arc identity, `sync_filesystem` each. Routed. |
| D3 | syncfs(2) | DONE | B633 #TBD | new `sys_syncfs`: resolve fd → `file.vfsmount().sb().sync_filesystem()` (whole fs, not one inode). Split out of the fsync arm. |
| D4 | shmat (SysV shm) | TODO | | `ipc/sysv_shm.rs:138` clones bytes per attach → not shared. One backing object shared by all attaches (real shmem). |
| D5 | chmod/chown/utimes ext4 persist (90/91/92/93/132/235/260/268/280/452) | TODO | | in-core only; add ext4 `InodeOps::setattr` + dirty/writeback in `vfs metadata set_perm/set_owner/set_times`. |

## P1 — non-functional facility / fake fd

| ID | Syscall(s) | Status | Branch | Fix |
|----|-----------|--------|--------|-----|
| F1 | userfaultfd | TODO | | `UFFDIO_REGISTER` records ranges but VMM fault path ignores them; `read()` returns 0 forever. Wire demand-fault → uffd_msg queue + WAKE. |
| F2 | pkey_alloc/free/mprotect (329-331) | TODO | | key handed out, never enforced (no PKRU). Either implement PKRU/CR4.PKE enforcement or ENOSYS like Linux w/o X86_FEATURE_PKU. |
| F3 | libaio io_setup/submit/getevents/cancel/destroy (206-210,333) | TODO | | `compat.rs:145` ENOSYS. Implement the aio ring (or keep ENOSYS only if truly matching Linux config — it does not). |
| F4 | quotactl / quotactl_fd (179/443) | TODO | | ENOSYS. Implement quota ops. |

## P1 — semantic gaps (real work done, contract broken)

| ID | Syscall(s) | Status | Branch | Fix |
|----|-----------|--------|--------|-----|
| G1 | kill(-1) broadcast (62) | DONE | B634 #TBD | `post_broadcast`: signal every real user proc the caller may signal, excluding self + init(vtgid 1) + kthreads(vtgid 0). Returns 0 / ESRCH. |
| G2 | nanosleep/clock_nanosleep EINTR (35/230) | TODO | | busy-yields, never checks sigpending, never writes `rem`. Make interruptible + write remaining. |
| G3 | getrusage/times (98/100) | TODO | | report wall-clock for utime, zeroed counters. Track real per-task CPU time + rusage counters. |
| G4 | set_robust_list exit walk (273) | TODO | | registers head but thread-exit never walks the robust list to wake futex waiters. |
| G5 | seccomp arg[5] (core.rs:26) | DONE | B635 #TBD | `check()` now passes the real `a5` (already read into args) instead of literal 0; filters inspecting args[5] evaluate correctly. |
| G6 | process_madvise/process_mrelease (440/448) | TODO | | fake success; resolve pidfd → target AS and apply advice / reap. |
| G7 | mlock family unmapped range (149-152) | DONE | B636 #TBD | split: `sys_mlock_range` (mlock/munlock) validates the page range via `find_vma` → ENOMEM on unmapped; `sys_mlockall` rejects bad MCL_* flags; `sys_munlockall` 0. |
| G8 | signalfd mask-update + siginfo (282/289) | TODO | | mask-update on existing fd no-op; siginfo only fills ssi_signo. |
| G9 | shmctl/semctl/msgctl IPC_STAT (31/191/71...) | TODO | | IPC_STAT/IPC_INFO return 0 without filling the user id_ds. Fill the struct. |

## P2 — cleanup

| ID | Syscall(s) | Status | Branch | Fix |
|----|-----------|--------|--------|-----|
| X1 | NR_LISTNS (470) | TODO | | declared, unrouted. Route to a real listns impl or drop the constant if not a real Linux syscall. |

## Notes
- Rows marked "not personally verified" in the audit (D5, D3, F1, F3, F4 + inotify/flock/xattr-persist semantics) get a source-read + hosted test as the FIRST step of their branch before implementing.
- Each branch: hosted test asserting the Linux-correct behavior (verify-left), both-arch build, PR. Boot-verify the security + corruption tier once landed.
