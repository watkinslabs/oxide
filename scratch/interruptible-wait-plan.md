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
| Sockets — INET/TCP/UDP/UNIX/VSOCK/netlink | 15 | `sock_intr_errno(timeo)` | `include/net/sock.h:2759` — DONE (F748) |
| pipe/FIFO read, write, open-partner | 4 | `-ERESTARTSYS` | `fs/pipe.c:481, 652, 1208` |
| tty read/write + job-control SIGTTIN/SIGTTOU | 5 | `-ERESTARTSYS` | `drivers/tty/n_tty.c:2155, 2356`; `tty_jobctrl.c:58` |
| eventfd, signalfd, timerfd, userfaultfd | 4 | `-ERESTARTSYS` | `fs/eventfd.c:232`, `fs/signalfd.c:181`, `fs/timerfd.c:314`, `mm/userfaultfd.c:3402` |
| FUSE request + `/dev/fuse` read | 2 | `-ERESTARTSYS` | `fs/fuse/dev.c:705, 1554` |
| `flock`, `F_SETLKW`, lease break | 3 | `-ERESTARTSYS` | `fs/locks.c:2233, 2537` |
| `syslog(2)` read | 1 | `-ERESTARTSYS` | `kernel/printk/printk.c:1611` |
| `mq_timedsend` / `mq_timedreceive` | 2 | `-ERESTARTSYS` | `ipc/mqueue.c:739` — DONE (F745) |
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
| DONE | 0 | Both primitives + ERESTART*-carrying error types + module-shim fix | `F744-wait-event-interruptible` |
| DONE | L0 | `mq_timedsend`/`mq_timedreceive`: no signal check (UNKILLABLE park) and `abs_timeout` discarded | `F745-mqueue-interruptible-timeout` |
| DONE | L1 | Robust-list PI decode (a PI entry aborted the walk) | `F746-robust-list-pi-decode` |
| DONE | L2 | `sigsuspend`/`msgsnd`/`msgrcv` ERESTARTNOHAND | `F747-sigsuspend-msg-restartnohand` |
| DONE | 1a | Sockets onto `sock_intr` (15 sites classified: 10 timed, 4 untimed, 1 already correct) | `F748-socket-sock-intr-errno` |
| DONE | 1b | pipe/FIFO/eventfd/fuse/uffd + tty job control (9 sites; autofs + uffd fault path NOT moved) | `F749-file-wait-erestartsys` |
| DONE | 1c | flock, F_SETLKW, syslog (SysV IPC + sigsuspend landed in F747, mqueue in F745) | `F750-lock-syslog-erestartsys` |
| DONE (no code) | 2 | alarm continuation ALREADY satisfied; CPU continuation is part of 3a — see §13 | `D398-phase2-already-satisfied` |
| TODO | 3a | CPU-time `clock_nanosleep` + its `posix_cpu_nsleep_restart` continuation (row 230 PARTIAL) — scoped in §14 | — |
| DEFERRED | 3c | PI futexes, 6 ops (row 202 PARTIAL) — successor project, NOT this lane: ~2500-3400 lines building rt_mutex + PI scheduling from scratch, needs its own design review | — |
| TODO | 4 | Only failures THIS work touches. The ext4-fsck / block-queue-limits / zram / vsock failures belong to their own lanes; adopting them here blurs responsibility. | — |

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

**3b — robust-list PI decode — CLOSED by F746.** All four defects fixed:
the bit-0 `FUTEX_ROBUST_MOD_PI` decode (`core.c:1085-1099`) that used to abort
the whole walk, PI suppression of the wake (`core.c:1074-1077`), the
`pending_op && !pi && !owner` wake-without-store case (`core.c:1022-1026`), and
the plain store replaced by cmpxchg-with-retry (`core.c:1052-1070`). Also
picked up Linux's fetch-next-before-handle ordering (`core.c:1136-1140`) and
the abort-walk-on-handler-failure rule (`core.c:1146-1148`).

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

## 9 Hosted-suite determinism (B1446 — DONE)

Four full-workspace runs over near-identical code gave 11 / 12 / 13 / 17
failures with a DIFFERENT set each time, so no run could distinguish a
regression from noise. One cause throughout: tests sharing process-global state
while cargo runs a binary's tests on parallel threads.

Measured before/after, `<fails>/<runs>`:

| Binary / module | Shared global | Before | After |
|---|---|---|---|
| `modules::linux_configfs` | callback counters (`RELEASES`, ...) | 9/12 | 0/24 |
| `modules::registry` | `REGISTRY` loaded-module table | 8/40 | 0/40 |
| `devfs::fs_tests` | devfs tree + `drv` device registry | 4/12 | 0/24 |
| `input` | `registry` input-device table | 3/24 | 0/24 |
| `sysfs::drm` | device model | 3/30 | 0/30 |
| `drv-virtio-input` | `registry` device table | 3/30 | 0/30 |
| `socket::receive_tests` | AF_UNIX in-flight/GC | 2/12 | 0/24 |
| `syscalls::quota_dispatch_hosted` | `CURRENT_TASK_PTR` | 2/30 | 0/40 |
| `netlink` | global FIB + `UEVENT_LISTENERS` | 1/12 | 0/60 |

Full workspace after: **9 failures in 4 of 5 runs**, same six names every time,
against 11/12/13/17-with-different-sets before.

Method notes:
- Test-owned state was preferred but is not available for these: every case is
  a kernel-wide SINGLETON (device registry, FIB, devfs tree, module table,
  AF_UNIX GC) that exists as a global by design. The alternative is inventing
  per-test registries inside the kernel, which is worse. `linux_configfs` is
  the one arguable case; its counters are written from `extern "C"` callbacks
  whose signatures are fixed ABI, and the only per-item context slot
  (`ConfigItem::private`) is itself ABI surface under test there.
- `netlink` needed ONE lock per GLOBAL, not per file: the FIB is written from
  four separate test files, so per-file locking still left them racing
  (measured 2/40 after per-file, 0/60 after per-global).
- All 281 `*LOCK.lock().unwrap()` sites in test harnesses now recover poison
  (`unwrap_or_else(|e| e.into_inner())`). A genuine failure used to poison the
  fixture lock and cascade into phantom extra failures — `fs::sys_dup2_shape`
  reported 2 failures for 1 real bug; it now reports 1.

### Remaining, NOT fixed here

| Item | Rate | Why not |
|---|---|---|
| `net::sock_rtnl_defer::process_context_final_drop_still_releases_inline` | 1/15 full runs, 0/40 isolated | Races the global `NetStack`/packet-socket registry shared with ~990 sibling tests in the same binary. Its own file-local lock is not enough. Fixing needs a crate-wide `net` serialisation or per-test namespaces — its own lane. |
| `fs::sys_close_shape::sys_close_uses_current_fdtable_and_removes_before_return` | ~2/20 full runs, 0/40 isolated | Same class: only fails under full-workspace load, passes in isolation. Undiagnosed. |

### Deterministic genuine failures (other lanes, deliberately NOT adopted)

Six, stable across every run: `ext4` `boot_like_balloc_into_uninit_group_keeps_fsck_clean`
and `concurrent_churn_keeps_fsck_clean`; `modules` `debugfs_automount_resolves_through_vfs_walk`
(6/6); `drv-zram` `final_swap_reference_reclaims_zram_slot`; `block`
`default_queue_limits_are_canonical_single_block_topology`; `socket`
`vsock_destination_and_interrupt_errors_match_linux` (6/6). Plus
`fs::sys_dup2_shape` reserved-target reservation (12/12).

## 10 1a outcome — classification, not a uniform sweep

15 sites, not the ~30 the first estimate guessed. Each checked against the
Linux function that owns it rather than pattern-matched:

| Group | Sites | Verdict |
|---|---|---|
| A — a real SO_{RCV,SND}TIMEO deadline in scope | 10 | `sock_intr(deadline)`: ERESTARTSYS untimed, EINTR timed |
| B — no timeout plumbed on that socket family | 4 | `sock_intr(NO_TIMEOUT)` = ERESTARTSYS, correct TODAY; see gap below |
| C — already correct, MUST NOT MOVE | 1 | `vsock/transaction.rs:191` |

**Group C detail.** AF_VSOCK connect waits on `vsk->connect_timeout`
(`af_vsock.c:1777`), default `VSOCK_DEFAULT_CONNECT_TIMEOUT = 2*HZ` and forced
back to the default if a setsockopt tries to set 0 (`af_vsock.c:2095-2099`). It
is therefore ALWAYS finite, so `sock_intr_errno(timeout)` yields `-EINTR`
(`af_vsock.c:1829`). Sweeping it to ERESTARTSYS would have been a regression.
That brings the do-not-touch list to 8.

**Group A partial-transfer rule.** `sk_stream_wait_memory` returns
`sock_intr_errno(*timeo)`, but `tcp_sendmsg_locked`'s `do_error:` returns the
PARTIAL count whenever anything was copied. Both send sites already had that
shape and keep it — only the nothing-copied arm changed.

### New gap found (NOT closed here)

AF_VSOCK and netlink honour **no** SO_RCVTIMEO / SO_SNDTIMEO in this tree
(`VsockSocket` has no timeo fields at all), so their waits are structurally
untimed and ERESTARTSYS is unconditionally correct — today. Linux DOES honour
them on both paths (`af_vsock.c:2267` send, `:2384` recv, off
`sock_{snd,rcv}timeo`; netlink via `skb_recv_datagram`). Once those options are
plumbed, those four sites must switch to the real deadline or they will report
ERESTARTSYS where Linux reports EINTR. Own lane.

B1447 makes that dependency visible IN CODE rather than only here: the sites
call the purpose-named `sock_intr::sock_intr_untimed_family_vfs()`, whose doc
comment states the contract and lists them, and both `VsockSocket` and
`NetlinkSocket` carry a block comment where the timeo fields WOULD be added
saying what else must change. Whoever plumbs the sockopt is reading the struct,
not this file — a trap recorded only in `scratch/` is the stale-doc problem
this campaign has already hit twice.

## 11 1b outcome — 9 changed, 2 deliberately not, count again below the estimate

The plan's grep-derived groups listed 5 rows totalling ~19 sites for 1b. The
real count reachable from `deliverable_signals_self` was 11, of which 9 moved.
Trust the classification over the plan estimate — same as 1a (15 vs ~30).

| Site | Linux | Verdict |
|---|---|---|
| `fs/pipe.rs` FIFO open x2 | `wait_for_partner`, `fs/pipe.c:1211` | ERESTARTSYS |
| `fs/pipe/ring.rs` read | `pipe_read`, `fs/pipe.c:476-481` | ERESTARTSYS |
| `fs/pipe/ring.rs` write | `pipe_write`, `fs/pipe.c:654` | ERESTARTSYS |
| `fs/pipe/eventfd.rs` read | `eventfd_read`, `fs/eventfd.c:232` | ERESTARTSYS |
| `fs/fuse/dev.rs` daemon read | `fuse_dev_do_read`, `fs/fuse/dev.c:1555` | ERESTARTSYS |
| `fs/fuse/conn.rs` request wait | `request_wait_answer`, `fs/fuse/dev.c:705` | ERESTARTSYS |
| `fs/userfaultfd/mod.rs` read | `userfaultfd_ctx_read`, `mm/userfaultfd.c:3401` | ERESTARTSYS |
| `console/jobctl.rs` background access | `__tty_check_change`, `tty_jobctrl.c:55-59` | ERESTARTSYS |
| `fs/autofs.rs` | `autofs/waitq.c:400` `wq->status = -EINTR` | **NOT moved** |
| `fs/userfaultfd/mod.rs` fault path | returns no errno — `break`s so the fault retries | **NOT moved** |

**tty job control is a second, different rule inside the same driver.** Linux
pairs `-ERESTARTSYS` with `set_thread_flag(TIF_SIGPENDING)` so a backgrounded
read RE-RUNS once SIGCONT continues the pgrp. With EINTR it failed permanently
instead of resuming after `fg`. The `Decision -> VfsError` mapping now lives in
the non-gated `tty::jobctl` with tests, so the console driver and the rule
cannot drift; its old doc comment said "Linux returns ERESTARTSYS; we surface
EINTR", a documented deferral now closed.

### New gap found (NOT closed here)

`fuse/conn.rs` aborts a request on the FIRST interruptible wait. Linux
`request_wait_answer` then runs a SECOND, **killable** phase (`fs/fuse/dev.c:721`)
after setting `FR_INTERRUPTED` and queueing a FUSE INTERRUPT request, so a
non-fatal signal does not abandon the request outright. The return code is
correct either way; the missing second phase is its own lane.

## 12 1c outcome — and a rule that must NOT be generalised

Three sites, all ERESTARTSYS: `flock(2)` (`fs/locks.c:2232`), `F_SETLKW` /
`F_OFD_SETLKW` (`:1480`, `:2536`), `syslog(2)` READ
(`kernel/printk/printk.c:1611`). The last two carried doc comments already
citing `wait_event_interruptible` while returning EINTR — documented deferrals,
now closed.

**`fs/locks.c` contains no `-EINTR` and no `-ERESTARTSYS` at all.** Every lock
wait is a bare `wait_event_interruptible` whose value propagates unchanged, so
the answer comes from `prepare_to_wait_event` (`kernel/sched/wait.c:309`). That
is the L1 primitive doing its job.

### The finding: `sock_intr_errno` is socket-specific, not a general rule

The lease break (`__break_lease`, `fs/locks.c:1764`) HAS a timeout
(`break_time`) and HAS an `-EWOULDBLOCK` path (`:1743`, `LEASE_BREAK_NONBLOCK`)
— and NEITHER changes the signal answer. `wait_event_interruptible_timeout`
returns `-ERESTARTSYS` on a signal whether or not a timeout was armed; the
timeout expiring returns 0, which `__break_lease` turns into success/retry
(`:1772-1781`), never EINTR.

So "a timed wait reports EINTR" is TRUE ONLY FOR SOCKETS, where
`sock_intr_errno` makes it so explicitly *because* the residual timeout cannot
cross a restart (`include/net/sock.h:2755-2757`). Do not carry that reasoning
into non-socket timed waits — several remain in phases 2/3a.

### Missing feature, not a wrong errno

This kernel has no blocking lease break at all: `vfs::file::lease_force_break`
revokes conflicting leases immediately and returns. Linux blocks the breaker in
`__break_lease` until the holder downgrades or `break_time` expires. Own lane.
Recorded in the matrix on row 72 (`fcntl`, which owns `F_SETLEASE`) as well as
here — the plan file is not where someone touching leases will look.

### The three 1c sites owe a CONFORMANCE test, not a hosted one

`flock(2)`, `F_SETLKW` and `syslog(2)` READ have ZERO verification beyond
reading Linux: no hosted coverage, and the boot reaches `basic.target` without
touching any of them, so the smoke run is compatible with the change but is not
evidence for it.

Inventing a non-gated seam purely to host-test them would be optimising the
metric — a seam no real caller uses proves nothing about the syscall. These are
real syscalls that userspace exercises heavily, just not before
`basic.target`, so the proof that actually closes them is a GUEST DIFFERENTIAL:
a program that blocks on a conflicting lock, takes a signal whose handler has
SA_RESTART, and observes the call RESUMING rather than failing — run against
both the host kernel (oracle) and oxide, same binary. Same host-oracle shape the
rename lane used. Until that exists these three remain the least-verified
changes in the sweep, and saying so is not the same as closing them.

Owed differential probes:
| Syscall | Probe |
|---|---|
| `flock(2)` | two fds, LOCK_EX contention, SIGALRM with SA_RESTART during the block |
| `fcntl F_SETLKW` | same over a byte range, plus the SA_RESTART-absent EINTR case |
| `syslog(2)` READ | block on an empty ring, signal, observe restart |

### Fuse two-phase gap now marked in code (B1447 pattern)

`RequestSlot` carries the marker where someone adding `FR_INTERRUPTED` /
FUSE_INTERRUPT would be reading, saying the wait must grow its second killable
phase with them. The ERESTARTSYS return is correct for both shapes, so nothing
else would flag the omission.

## 13 Phase 2 — no code to write, and why

Scoped as "the two missing `restart_block` continuations". Classified against
Linux before writing, per the vsock lesson. Both halves dissolve.

### `alarm_timer_nsleep_restart` — already satisfied

`alarm_timer_nsleep` (`kernel/time/alarmtimer.c:766-805`) ends with EXACTLY the
split `hrtimer_nanosleep` uses:

    if (ret != -ERESTART_RESTARTBLOCK) return ret;
    if (flags == TIMER_ABSTIME) return -ERESTARTNOHAND;   /* :798-800 */
    restart->nanosleep.clockid = type;
    restart->nanosleep.expires = exp;
    set_restart_fn(restart, alarm_timer_nsleep_restart);

F743 put that split in the shared engine, and `230_clock_nanosleep` routes the
alarm clocks through it unconditionally — `sleep_until_deadline(cur, deadline,
rem, is_abs)` is called for every clock id. So the alarm ABS/REL restart
behaviour is already Linux's.

A separate `RESTART_ALARM_NANOSLEEP` kind would be pure ceremony: same payload
(absolute expiry + rmtp), same resume, no observable difference. Linux needs a
distinct continuation only because it resumes against `alarm_bases[type]` with
RTC wake-from-suspend; note it even REUSES `nanosleep.clockid` to store an
`alarmtimer_type`, not a clockid (`alarmtimer.c:748`) — a sibling in shape only.

**The real alarm gap is not the restart block.** This kernel has no alarm timer
base and no RTC-backed wake-from-suspend, and returns no `-EOPNOTSUPP` for a
missing rtcdev (`alarmtimer.c:775-776`). CAP_WAKE_ALARM is checked correctly.
Because no system-suspend path exists here at all, an alarm sleep is
behaviourally identical to Linux's on a machine that never suspends — the
distinguishing semantics are unobservable. Own lane, gated on suspend support.

### `posix_cpu_nsleep_restart` — not separable from 3a

It cannot exist before CPU-time sleeping does: it re-enters
`do_cpu_nanosleep(which_clock, TIMER_ABSTIME, &t)`
(`posix-cpu-timers.c:1657-1665`). It is a component of 3a, not a phase of its
own, and is folded into §14.

### Rule carried forward from 1c

Neither continuation is a "timed wait ⇒ EINTR" case. `sock_intr_errno` is
socket-specific; both nanosleep families use the ABS/REL split instead, which
keys on the REQUEST form, not on whether a timeout was armed.

## 14 Phase 3a scope, sized against what exists

Linux does not convert CPU clocks to a wall deadline at all. `do_cpu_nanosleep`
(`posix-cpu-timers.c:1537-1626`) arms a stack `k_itimer` with
`it.cpu.nanosleep = true`, which makes `cpu_timer_fire`
(`:684-688`) WAKE THE SLEEPER instead of queueing a signal. This kernel
converts every clock to an absolute monotonic deadline, so a process-CPU sleep
expires on elapsed time — wrong whenever the task is not the only runnable one.

Already present and reusable:
| Piece | Location |
|---|---|
| per-task + thread-group CPU accounting | `task.rs:405-408`, `thread_group.rs:226-235` |
| CPU time charged on the tick | `cpustat.rs:91-105` |
| CPU-clock sampling by domain | `timers/clock.rs:88-99` `cpu_now_ns` |
| CPU-timer expiry on the accounting tick | `timers/runtime.rs:121-138` `account_cpu_tick` |
| restart-block kinds + slot-219 dispatch | `sched::task::restart`, `219_restart_syscall.rs` |
| clock admission (EOPNOTSUPP for THREAD_CPUTIME) | `timers/clockid.rs:192-201` — already Linux-correct |

Remaining work: a per-task CPU-sleep deadline checked in `account_cpu_tick`
beside the existing ITIMER_VIRTUAL/PROF checks; routing CPU clocks in
`230_clock_nanosleep` away from the monotonic engine; a `RESTART_CPU_NANOSLEEP`
kind carrying clockid + absolute CPU expiry; and `posix_cpu_nsleep`'s `-EINVAL`
for a per-thread clock naming self (`posix-cpu-timers.c:1639-1642`).

Related divergence to fix in the same lane: `CpuMeasure::Sched` is
`utime+stime` (`timers/clock.rs:82-96`) where Linux's `CPUCLOCK_SCHED` is
`task_sched_runtime()`, and `clock_getres` already advertises 1 ns
(`clockid.rs:137`).
