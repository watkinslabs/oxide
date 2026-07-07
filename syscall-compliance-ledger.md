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
| D1 | pwritev / pwritev2 (296/328) | TODO | | `296_pwritev.rs` forwards to `writev`, dropping the offset → positional writes hit `f_pos`. Plumb the `pos_l`/`pos_h` offset like `preadv` (295) already does. |
| D2 | sync(2) | TODO | | `route_b.rs:99` `NR_SYNC => 0` no-op. Iterate `vfs::mount::MOUNTS` calling `SuperBlock::sync_filesystem`. |
| D3 | syncfs(2) | TODO | | `074_fsync.rs` flushes only the fd's inode. Route SYNCFS to the fd's superblock `sync_filesystem`. |
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
| G1 | kill(-1) broadcast (62) | TODO | | `062_kill.rs:58` returns EPERM. Signal every process the caller may signal (except self/init per Linux). |
| G2 | nanosleep/clock_nanosleep EINTR (35/230) | TODO | | busy-yields, never checks sigpending, never writes `rem`. Make interruptible + write remaining. |
| G3 | getrusage/times (98/100) | TODO | | report wall-clock for utime, zeroed counters. Track real per-task CPU time + rusage counters. |
| G4 | set_robust_list exit walk (273) | TODO | | registers head but thread-exit never walks the robust list to wake futex waiters. |
| G5 | seccomp arg[5] (core.rs:26) | TODO | | `check()` passes hardcoded 0 for the 6th arg. Plumb real a5. |
| G6 | process_madvise/process_mrelease (440/448) | TODO | | fake success; resolve pidfd → target AS and apply advice / reap. |
| G7 | mlock family unmapped range (149-152) | TODO | | returns 0 for unmapped ranges; Linux returns ENOMEM. Validate range. |
| G8 | signalfd mask-update + siginfo (282/289) | TODO | | mask-update on existing fd no-op; siginfo only fills ssi_signo. |
| G9 | shmctl/semctl/msgctl IPC_STAT (31/191/71...) | TODO | | IPC_STAT/IPC_INFO return 0 without filling the user id_ds. Fill the struct. |

## P2 — cleanup

| ID | Syscall(s) | Status | Branch | Fix |
|----|-----------|--------|--------|-----|
| X1 | NR_LISTNS (470) | TODO | | declared, unrouted. Route to a real listns impl or drop the constant if not a real Linux syscall. |

## Notes
- Rows marked "not personally verified" in the audit (D5, D3, F1, F3, F4 + inotify/flock/xattr-persist semantics) get a source-read + hosted test as the FIRST step of their branch before implementing.
- Each branch: hosted test asserting the Linux-correct behavior (verify-left), both-arch build, PR. Boot-verify the security + corruption tier once landed.
