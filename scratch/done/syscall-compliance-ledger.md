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
| S3 | prctl(157), capset(126), setresuid(117) capability transition | FIXED — x86 live boot | B1257 | Unified `PR_SET_KEEPCAPS` with `SECBIT_KEEP_CAPS`; the UID drop retains permitted capabilities when Linux securebits require it, allowing systemd's ambient capability raise. Enforced securebits locks, rejected ambient raise when prohibited, and cleared ambient bits when capset/UID transition invalidates them. The live x86 run no longer reports `user@1000.service` status `218/CAPABILITIES`. |
| S4 | prctl(157) `PR_SET_TIMERSLACK` / `PR_GET_TIMERSLACK` | PARTIAL | B1257 | Implemented canonical, fork-inherited per-task timer-slack state (50µs default; a zero setter restores that default), removing the live GNOME `rtkit-daemon` `EINVAL`. Remaining Linux behavior: sleep/futex/poll deadline coalescing must consume this state; do not mark complete until that is wired. |
| S5 | rt_sigtimedwait(128) blocking wait | FIXED — x86 live task dump | B1257 | Replaced the busy yield with a race-safe signal wait-list park, scheduler deadline wake, and delivery escape for unrelated signals. The post-fix live dump held the user-manager child in `Sleeping` state at 27 entries across 20 seconds (instead of >41k entries); the separate `user@1000.service` readiness timeout remains open in G11. |
| S6 | sendto(44), sendmsg(46) AF_UNIX pathname resolution | FIXED — x86 live boot | B1257 | Unified the socket work-layer's fallback root with the task mount namespace. A user manager with no explicit `root_vfs` now resolves `/run/systemd/notify` against its namespace root, rather than the global root; its `READY=1` reaches PID 1. Socket suite: 36 passed. |
| S1 | seccomp fork/exec inheritance | DONE | B631 #2795 | `spawn_user_thread_for_fork` (both arches) now clones parent `seccomp_filters` into child; execve never clears it. |
| S2 | landlock fork/exec inheritance | DONE | B631 #2795 | same site: child clones parent `landlock_chain`. |

## P0 — data corruption / false durability (verified)

| ID | Syscall(s) | Status | Branch | Fix |
|----|-----------|--------|--------|-----|
| D1 | pwritev / pwritev2 (296/328) | DONE | B632 #TBD | `296_pwritev.rs` now a positional write mirroring `preadv`: extracts pos_l/pos_h, writes each iovec at the running offset via `inode().write(off,buf)`, never touches `f_pos`. |
| D2 | sync(2) | DONE | B633 #TBD | new `162_sync.rs sys_sync`: iterate `all_mounts()`, dedup superblocks by Arc identity, `sync_filesystem` each. Routed. |
| D3 | syncfs(2) | DONE | B633 #TBD | new `sys_syncfs`: resolve fd → `file.vfsmount().sb().sync_filesystem()` (whole fs, not one inode). Split out of the fsync arm. |
| D4 | shmat (SysV shm) | DONE | B639 #TBD | ShmSegment now holds ONE shared shmem backing (anon tmpfs inode, built by new `029_shmget.rs` shim); every shmat maps it MAP_SHARED so attaches + forked children share frames. Replaces the per-attach `bytes.clone()`. |
| D5 | chmod/chown/utimes ext4 persist (90/91/92/93/132/235/260/268/280/452) | DONE | B641 #TBD | syscall `notify_change` now routes the apply through VFS `i_op->setattr` (Linux `fs/attr.c`); ext4 overrides `setattr` (`ext4_setattr`) to journal mode/owner(+osd2 hi)/times to the on-disk inode. Read side: ext4 inode decoder now parses atime/ctime/mtime(+`i_*time_extra` ns) and iget threads them via `InodeBuilder::times`, so utimes round-trips. Hosted `setattr_persist_image` proves chmod+chown(>16-bit)+utimes(ns) survive a remount. |

## P1 — non-functional facility / fake fd

| ID | Syscall(s) | Status | Branch | Fix |
|----|-----------|--------|--------|-----|
| F1 | userfaultfd | DONE | B642 #TBD | MISSING-mode fully wired: mm-vmm `UffdContext` trait + per-VMA ctx (`VMA_UFFD_MISSING`); mm-pmm `do_handle` intercepts a NotPresent fault in a registered range → enqueue PAGEFAULT `uffd_msg`, wake monitor, park faulter (no vmas lock held). fs `read`/`poll` block; `UFFDIO_COPY`/`ZEROPAGE` alloc real frames + `map_at` into the faulting AS + wake; `WAKE`/`UNREGISTER` wired. Fork clears child uffd (no EVENT_FORK). Fixed `uffd_msg` ABI (address@16, was swapped). WP recorded-only (honest, not faked). Boot-verified: userspace `uffd_probe` (monitor+faulter threads) → PASS. |
| F2 | pkey_alloc/free/mprotect (329-331) | DONE | B640 TBD | key handed out, never enforced (no PKRU). Either implement PKRU/CR4.PKE enforcement or ENOSYS like Linux w/o X86_FEATURE_PKU. |
| F3 | libaio io_setup/submit/getevents/cancel/destroy (206-210,333) | DONE | B643 #TBD | new `aio.rs`: process-global context registry (opaque `aio_context_t` id); io_submit runs each iocb INLINE via the real pread64/pwrite64/preadv/pwritev/fsync work fns (full gate chain) then queues the io_event; io_getevents copies out (validate-before-dequeue). Vectored ops pack offset per-arch (x86 pos_l/pos_h split) so PREADV>4GiB doesn't truncate. RESFD eventfd signal; io_cancel EINVAL (nothing in-flight, Linux-faithful). ENOSYS arm removed; 6 slots wired to route_a. Boot-verified: `/bin/aio_probe` (io_setup→submit PREAD→getevents, res==8+content) → PASS. |
| F4 | quotactl / quotactl_fd (179/443) | DONE | B644 #2819 | faithful no-quota-active dispatch: Q_SYNC→0, GET*/state→ESRCH, mutate→EPERM w/o CAP_SYS_ADMIN, len!=… decode; NOT ENOSYS (Linux w/ CONFIG_QUOTA doesn't ENOSYS it). Boot-verified `/bin/quota_probe` → PASS. (Row was left WIP by a merge race; code merged in #2819.) |

## P1 — semantic gaps (real work done, contract broken)

| ID | Syscall(s) | Status | Branch | Fix |
|----|-----------|--------|--------|-----|
| G1 | kill(-1) broadcast (62) | DONE | B634 #TBD | `post_broadcast`: signal every real user proc the caller may signal, excluding self + init(vtgid 1) + kthreads(vtgid 0). Returns 0 / ESRCH. |
| G2 | nanosleep/clock_nanosleep EINTR (35/230) | DONE | B638 #2803 | both loops now check `pending & !sigmask` each iteration → EINTR + write `rem` (TIMER_ABSTIME skips rem). |
| G3 | getrusage/times (98/100) | DONE | B645 #TBD | real per-task utime/stime via tick-sampling (Linux CONFIG_TICK_CPU_ACCOUNTING): both arch timer ISRs charge the real inter-tick monotonic delta to the interrupted task's utime (from_user) or stime bucket via `cpustat::charge_current_tick` (timer isn't fixed 100Hz here, so real-delta not jiffy; clamped 100ms). New Task utime_ns/stime_ns + cumulative_child_{u,s}time_ns; getrusage/times read them; child time rolls up on reap (signal_child_exit). ru_maxrss/faults stay 0 (out of scope). Boot-verified `/bin/cputime_probe` (user busy-loop → ru_utime>0 && tms_utime>0) → PASS. |
| G4 | set_robust_list exit walk (273) | DONE | B646 #TBD | core walk+sys_exit wiring already merged; B646 closed the crash paths: exit_robust_list now runs on the fatal-signal path (zombies terminate) + both SIGSEGV terminate paths (mm-pmm signal.rs x86/arm) via a sched robust-exit hook (walk body in ipc). Fault-SAFE: new `user_addr_accessible` translate-present guard on every user read/write in robust.rs (a crashing task's corrupt list can't kernel-#PF). Linux parity: set_robust_list len!=24→EINVAL. Boot-verified `/bin/robust_probe` → OWNER_DIED set on owner exit + EINVAL check → PASS. |
| G5 | seccomp arg[5] (core.rs:26) | DONE | B635 #TBD | `check()` now passes the real `a5` (already read into args) instead of literal 0; filters inspecting args[5] evaluate correctly. |
| G6 | process_madvise/process_mrelease (440/448) | DONE | B647 #TBD | both real now. madvise: pidfd→task, sig_perm_check, read_iovs, advice validated to the {WILLNEED,DONTNEED,FREE,COLD,PAGEOUT} subset; DONTNEED/FREE drop the target's pages (self→active-root evict, foreign→new evict_foreign_pages_in_range built on hal unmap_4k_at_root + the SAME rmap_aware_dec_and_maybe_free), COLD/PAGEOUT/WILLNEED no-op (no LRU/swap). mrelease: pidfd→task, reject self, require exiting(SIGKILL/Zombie), sig_perm_check, then reaps the target's ANON pages in place (OOM-reaper style, mm stays attached — detaching would let a dying user task return to user against the wrong CR3). Boot-verified `/bin/pmadvise_probe` (DONTNEED→refault-zero + self-mrelease EINVAL) → PASS. |
| G7 | mlock family unmapped range (149-152) | DONE | B636 #TBD | split: `sys_mlock_range` (mlock/munlock) validates the page range via `find_vma` → ENOMEM on unmapped; `sys_mlockall` rejects bad MCL_* flags; `sys_munlockall` 0. |
| G8 | signalfd mask-update + siginfo (282/289) | DONE | B648 #TBD | signalfd(fd>=0) now stores the new mask on the existing SignalfdData (EINVAL if not a signalfd); read fills the full signalfd_siginfo — pops the signal's queued siginfo (rt_sigqueue for RT 33-64, new child_sigq_pop for SIGCHLD) and writes ssi_signo + ssi_code/pid/uid and ssi_status (SIGCHLD, from wait-encoded value) or ssi_int/ssi_ptr (RT sigqueue value); other standard sigs → ssi_signo only. Boot-verified `/bin/signalfd_probe` (re-arm to SIGCHLD, fork+exit(42) → ssi_signo=17,pid=child,status=42,code=CLD_EXITED) → PASS. |
| G9 | shmctl IPC_STAT (31) | DONE | B639 #TBD | shmctl IPC_STAT now fills shmid64_ds (key/mode/shm_segsz/shm_cpid/shm_nattch) instead of zeroing. sem/msg IPC_STAT fills remain as follow-up. |
| G10 | clone/clone3 child exit signal (56/435) | FIXED — hosted contract test | B1257 | Unified clone validation now rejects invalid exit signals and nonzero exit signals with `CLONE_THREAD`/`CLONE_PARENT`. Zombie publication now honors the child’s stored exit signal: zero is silent, SIGCHLD carries child status through `child_sigq`, and real-time signals retain queued child-exit siginfo. |

## P2 — cleanup

| ID | Syscall(s) | Status | Branch | Fix |
|----|-----------|--------|--------|-----|
| X1 | NR_LISTNS (470) | DONE | B637 #TBD | not a real mainline syscall (proposed, never merged); removed the fictional constant. |

## Notes
- Rows marked "not personally verified" in the audit (D5, D3, F1, F3, F4 + inotify/flock/xattr-persist semantics) get a source-read + hosted test as the FIRST step of their branch before implementing.
- Each branch: hosted test asserting the Linux-correct behavior (verify-left), both-arch build, PR. Boot-verify the security + corruption tier once landed.
