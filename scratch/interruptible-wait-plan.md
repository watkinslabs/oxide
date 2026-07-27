# Interruptible-wait conformance plan

Root cause of the `EINTR`-instead-of-`ERESTARTSYS` defect class, and the lanes
that close it. Opened after F743 fixed 5 syscalls and found they were 5 call
sites of a primitive this kernel never built.

## 1 Root cause

Linux funnels every interruptible sleep through `___wait_event`
(`include/linux/wait.h:302-327`) → `prepare_to_wait_event`
(`kernel/sched/wait.c:289-320`), which returns **`-ERESTARTSYS`** at
`wait.c:309` when `signal_pending_state()` holds. `-ERESTARTSYS` is therefore
Linux's DEFAULT for an interrupted wait; a real `-EINTR` is the deliberate
exception a syscall opts into.

Sockets have a second shared rule on top: `sock_intr_errno`
(`include/net/sock.h:2755-2761`) returns `-ERESTARTSYS` when no
SO_{RCV,SND}TIMEO is set and `-EINTR` when one is — *"Alas, with timeout socket
operations are not restartable."*

Oxide had neither primitive. 46 hand-rolled loops each re-implement
enqueue / signal-check / recheck / park, and every one picked `-EINTR`.

| Layer | Defect | Owner | Phase 0 |
|---|---|---|---|
| L1 | No `wait_event_interruptible` equivalent | `sched::live::wait_event` + `sched::task::sigwake` | DONE |
| L1b | No `sock_intr_errno` equivalent (~30 socket sites) | `net::sock_intr` | DONE |
| L2 | `VfsError`/`NetError`/`socket::Error` are errno enums with no ERESTART* variant, so a correct wait is FLATTENED to `Eintr` before the shim sees it | the three error enums | DONE |
| L3 | `restart_block` has 3 of Linux's 5 clients | `sched::task::restart` | Phase 2 |

L2 is why the 46 sites *could not* have been right: the type system forbade the
correct answer.

## 2 Per-syscall ground truth

Audited against Linux source. **Already correct in oxide — do not touch:**
`epoll_wait` (`fs/eventpoll.c:2287`, genuine `-EINTR`, corroborated by
`restore_saved_sigmask_unless(error == -EINTR)` at `:2843`), `semop`
(`ipc/sem.c:2158`, genuine `-EINTR`, no ERESTART anywhere in `ipc/sem.c`),
`rt_sigtimedwait` (`kernel/signal.c:3803`), autofs (`fs/autofs/waitq.c:400`),
`VT_WAITACTIVE` (`drivers/tty/vt/vt_ioctl.c:230`), `getdents`
(`fs/readdir.c:282`, partial count, no errno), `wait4`/`waitid`, plus the five
F743 fixed. `mutex_lock_interruptible` (`kernel/locking/mutex.c:713`) and
`down_interruptible` (`kernel/locking/semaphore.c:307`) are genuinely `-EINTR`.

**Wrong today:**

| Group | Sites | Correct code | Linux |
|---|---|---|---|
| Sockets — INET/TCP/UDP/UNIX/VSOCK/netlink | ~30 | `sock_intr_errno(timeo)` | `include/net/sock.h:2759` |
| pipe/FIFO read, write, open-partner | 4 | `-ERESTARTSYS` | `fs/pipe.c:481, 652, 1208` |
| tty read/write + job-control SIGTTIN/SIGTTOU | 5 | `-ERESTARTSYS` | `drivers/tty/n_tty.c:2155, 2356`; `tty_jobctrl.c:58` |
| eventfd, signalfd, timerfd, userfaultfd | 4 | `-ERESTARTSYS` | `fs/eventfd.c:232`, `fs/signalfd.c:181`, `fs/timerfd.c:314`, `mm/userfaultfd.c:3402` |
| FUSE request + `/dev/fuse` read | 2 | `-ERESTARTSYS` | `fs/fuse/dev.c:705, 1554` |
| `flock`, `F_SETLKW`, lease break | 3 | `-ERESTARTSYS` | `fs/locks.c:2233, 2537` |
| `syslog(2)` read | 1 | `-ERESTARTSYS` | `kernel/printk/printk.c:1611` |
| `msgsnd` / `msgrcv` | 2 | `-ERESTARTNOHAND` | `ipc/msg.c:930, 1241` |
| `rt_sigsuspend` / `sigsuspend` | 1 | `-ERESTARTNOHAND` | `kernel/signal.c:4853` |
| `mq_timedsend` / `mq_timedreceive` | 2 | `-ERESTARTSYS` | `ipc/mqueue.c:739` |
| module shim `completion_wait` | 1 | `-ERESTARTSYS` | `kernel/sched/completion.c:93` |

**`mq_timedsend`/`mq_timedreceive` (`ipc/src/live/posix_mq.rs:319,357`) have no
signal check at all** — an unkillable park. Worse than the rest of the class.

`recvmmsg`/`sendmmsg` are special: a partial batch returns the count and stashes
the error in `sk_err` (`net/socket.c:3079-3097`, `:2844-2848`).

oxide has **no io_uring blocking wait at all** (`426_io_uring_enter.rs` has no
`min_complete` path) — a missing feature, not a wrong code.

## 3 Lanes

| Status | Phase | Item | Branch |
|---|---|---|---|
| IN-PROGRESS | 0 | Both primitives + ERESTART*-carrying error types + module-shim fix | `F744-wait-event-interruptible` |
| TODO | 1a | Sockets onto `sock_intr` (~30 sites) | — |
| TODO | 1b | pipe/tty/console/eventfd/timerfd/signalfd/uffd/fuse | — |
| TODO | 1c | locks, syslog, SysV IPC, mqueue signal check, sigsuspend | — |
| TODO | 2 | `alarm_timer_nsleep_restart` + `posix_cpu_nsleep_restart` | — |
| TODO | 3a | CPU-time `clock_nanosleep` (row 230 PARTIAL) | — |
| TODO | 3b | Robust-list PI decode fixes (latent bug, do before 3c) | — |
| TODO | 3c | PI futexes, 6 ops (row 202 PARTIAL) | — |
| TODO | 4 | 12 failing hosted tests | — |

## 4 Phase 0 scope (this branch) — DONE

1. `sched::live::wait_event` — Linux `___wait_event`'s loop; `WaitState` /
   `WaitOutcome` / `signal_pending_state` live in the NON-gated
   `sched::task::sigwake` so the decision is hosted-tested.
   `__fatal_signal_pending` is SIGKILL only (`sched/signal.h:399-402`), not
   SIGSTOP.
2. `net::sock_intr` — `sock_intr_errno`, non-gated, with `NetError`/`VfsError`
   flavours for the two ways a socket wait exits.
3. `Erestartsys = 512` on `VfsError`, `NetError`, `socket::Error` + `From` arms.
4. `modules/src/linux_sync.rs` `prepare_to_wait_event` returned a flat `0` — it
   never checked `signal_pending_state`, so every module-side
   `wait_event_interruptible` was UNINTERRUPTIBLE. Now returns
   `-ERESTARTSYS`; `completion_wait_common` corrected from `-EINTR`.
5. `metadata/index.md` F counter was stale (`next=731` with F743 merged).

Phase 0 does NOT migrate call sites — foundation before wiring, so the
primitive is THE path from the start rather than a fallback bolted beside 46
survivors.

## 5 Phase 2 — the two missing restart_block clients

Linux has exactly five continuations (`include/linux/restart_block.h:26-55`
has three union members; an exhaustive `->fn =` grep yields five fns):
`do_restart_poll`, `futex_wait_restart`, `hrtimer_nanosleep_restart` (all
present), plus:

| Missing | Linux | Arming syscall |
|---|---|---|
| `alarm_timer_nsleep_restart` | `kernel/time/alarmtimer.c:805` | `clock_nanosleep(CLOCK_{REALTIME,BOOTTIME}_ALARM)`, relative only |
| `posix_cpu_nsleep_restart` | `kernel/time/posix-cpu-timers.c:1657` | `clock_nanosleep` on a CPU clock, relative only |

Both use the `nanosleep` union; both return `-ERESTARTNOHAND` for ABSTIME.

## 6 Phase 3a — CPU-time `clock_nanosleep` (small: ~150-250 lines)

Linux does not convert CPU clocks to a wall deadline at all: `clock_nanosleep`
dispatches through `k_clock::nsleep` (`posix-timers.c:1404`), and the CPU arm
`do_cpu_nanosleep` (`posix-cpu-timers.c:1537-1626`) arms a stack `k_itimer`
with `it.cpu.nanosleep = true`, which makes `cpu_timer_fire`
(`posix-cpu-timers.c:684-688`) **wake the sleeper instead of queueing a
signal**. `CLOCK_THREAD_CPUTIME_ID` has no `.nsleep` → EOPNOTSUPP; a per-thread
CPU clock naming self is `-EINVAL` (`posix-cpu-timers.c:1639-1642`).

oxide already has everything needed: per-task and thread-group CPU accounting
(`task.rs:405-408`, `thread_group.rs:226-235`, charged at `cpustat.rs:91-105`),
POSIX CPU timers with CPU-relative arming (`timers/syscalls.rs:89-121`,
`timers/clock.rs:101-110`), CPU-timer expiry on the accounting tick
(`timers/runtime.rs:121-138`), restart blocks, and the shared sleep engine.
Recommended shape: a `cpu_sleep_deadline_ns: AtomicU64` on `Task` checked in
`account_cpu_tick` beside the existing ITIMER_VIRTUAL/PROF checks.

Known related gap: oxide's `CpuMeasure::Sched` is `utime+stime`
(`timers/clock.rs:82-96`), but Linux's `CPUCLOCK_SCHED` is `task_sched_runtime()`
— ns-exact, while `clock_getres` already claims 1 ns (`clockid.rs:137`).

## 7 Phase 3b/3c — PI futexes (large: ~2500-3400 lines)

oxide returns `-ENOSYS` for all six PI ops (`futex/wait.rs:98-100`), which is
what Linux does only with `CONFIG_FUTEX_PI=n`.

**3b first — robust-list PI decode is a latent bug today.** `robust.rs:24-33`
requires 8-alignment on the list pointer, but Linux masks `FUTEX_ROBUST_MOD_PI`
off bit 0 (`core.c:1083-1096`); a PI robust entry therefore aborts the whole
walk. Also missing: PI suppression of the wake (`core.c:1073` gates on `!pi`),
the `pending_op && !pi && !owner` case (`core.c:1019-1025`), and the store is a
plain write rather than a cmpxchg with retry (`core.c:1069-1070`). ~80 lines,
independent of 3c.

**3c is a from-scratch subsystem.** oxide has no rt_mutex and no priority
inheritance anywhere (`live/mutex.rs:13-15` says so explicitly; no
`pi_waiters`/`pi_blocked_on`/`normal_prio` on `Task`). It does have an RT
runqueue (`rt.rs:18-79`) and a correct class-migrating requeue primitive
(`runqueue.rs:243-260`) that is the right half of `rt_mutex_setprio`. The
critical path is `rt_mutex_adjust_prio_chain` plus the CFS↔RT boosting.
Ordering: rt_mutex + scheduler plumbing → pi_state + LOCK_PI/UNLOCK_PI/TRYLOCK_PI
(+ priority-ordered waiter list, replacing the flat `WAITERS: Vec` at
`core.rs:75`, + a cmpxchg uaccess primitive) → `exit_pi_state_list` and the
futex exit states, which must land WITH the previous step or a task holding a
PI futex at exit strands every waiter → `CMP_REQUEUE_PI`/`WAIT_REQUEUE_PI`
last (PI condvars only; `-ENOSYS` for those two while `LOCK_PI` works is a
coherent intermediate state).

## 8 Known-broken tests (Phase 4)

| Test | Crate | Note |
|---|---|---|
| `vsock_destination_and_interrupt_errors_match_linux` | `socket` | `Epipe` vs `Eintr` — in this defect family |
| `write_path_produces_e2fsck_clean_image`, `htree_leaf_split_stays_e2fsck_clean` | `ext4` | |
| `boot_like_balloc_into_uninit_group_keeps_fsck_clean`, `concurrent_churn_keeps_fsck_clean` | `ext4` | |
| `default_queue_limits_are_canonical_single_block_topology` | `block` | |
| `final_swap_reference_reclaims_zram_slot` | `drv-zram` | |
| `debugfs_automount_resolves_through_vfs_walk` | `modules` | |
| `sys_dup2_reserved_target_is_ebusy_and_preserves_reservation`, `sys_dup2_without_current_or_fdtable_is_ebadf` | `fs` | |
| hosted zram PMM provider `Ebusy` | `pmm` | |
| `try_populate_defaults_is_idempotent_for_existing_pseudo_devices` | `devfs` | order-dependent global state; passes in isolation |
| `lookup_prefers_longest_prefix` | `netlink` | order-dependent global state; passes in isolation |

Baseline on `origin/main` at F743 merge: 7728 passed / 12 failed / 7 ignored.
