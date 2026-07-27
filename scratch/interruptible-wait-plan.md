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
| DONE | 3a | CPU-time `clock_nanosleep` + `RESTART_CPU_NANOSLEEP` | `F751-cpu-time-clock-nanosleep` |
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

**CLOSED by F752** — the options are plumbed, so no site depends on a field's
absence any more and the markers are deleted. Historical note follows.

B1447 made that dependency visible IN CODE rather than only here: the sites
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

**Correction (B1451).** 1b fixed the errno but only the CONSOLE driver ever ran
the gate, and no pty was ever a controlling terminal, so the rule was
unreachable on `/dev/pts/<n>` — the ttys every job-control shell actually uses.
The `wait_diff` `jobctl` probe timed out on BOTH arches. Two missing links, both
closed in B1451: `console::acquire_ctty_on_open` short-circuits outside the
console char-device band, so a pty slave open never acquired a ctty
(`drivers/tty/tty_io.c:2163-2169` folds only the MASTER half into `noctty`), and
`PtySlaveFileOps::{read,read_nonblock,write}` never called the gate at all
(`drivers/tty/n_tty.c:2200`). The live gate moved `console::jobctl` →
`tty::jobctl::live` so both drivers share one; `console` is a
`target_os = "oxide-kernel"` crate devpts cannot depend on, which is how the
split survived review.

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

## 15 Phase 3a — concrete design, and two admission divergences found

### The wake mechanism: reuse the PosixTimer slot, do not invent state

`do_cpu_nanosleep` (`posix-cpu-timers.c:1537-1626`) allocates a TEMPORARY
`k_itimer` on the stack, sets `timer.it.cpu.nanosleep = true`, arms it with
`posix_cpu_timer_set(&timer, flags, &it, NULL)` (so TIMER_ABSTIME rides the
same arming path as a real timer), then blocks TASK_INTERRUPTIBLE until it
fires. The whole trick is in `cpu_timer_fire` (`:682-688`):

    if (unlikely(ctmr->nanosleep)) {
        wake_up_process(timer->it_process);   /* NOT a signal */
        cpu_timer_setexpires(ctmr, 0);
    } else {
        posix_timer_queue_signal(timer);
    }

Why it must be event-driven, not a poll: **a task asleep accrues no CPU time**,
so a CPU-clock sleep can only be advanced by whichever SIBLING is running. That
is exactly why the wake fires from the accounting path and why Linux EINVALs a
per-thread clock naming self — such a sleep could never complete.

This kernel already has every piece: `thread_group.posix_timers` slots serviced
by `account_cpu_tick` (`timers/runtime.rs:121-138`) on the RUNNING task, CPU
sampling per domain (`timers/clock.rs:88-99`), and an IRQ-safe wake
(`ttwu_deferred`, used by `post_to` at `timers/runtime.rs:38-43`). So the
implementation is: add `nanosleep: bool` + `sleeper_tid: u32` to `PosixTimer`
(`timers/model.rs:52-62`), and in `service_wake` (`runtime.rs:54-59`) take the
wake branch instead of `post` when `nanosleep` is set. That mirrors Linux
structurally rather than bolting on a parallel mechanism, and needs no new
per-task state and no new IRQ path.

Then: `230_clock_nanosleep` routes `ClockSpec::Cpu*` to that instead of the
monotonic engine; a `RESTART_CPU_NANOSLEEP` kind carries clockid + the ABSOLUTE
CPU expiry (`restart->nanosleep.expires = ns_to_ktime(expires)`, `:1616`); and
the ABS/REL split is the SAME one F743 already owns (`:1647-1653`).

### Admission ladder — two divergences, found while sizing

`nsleep_supported` (`timers/clockid.rs:192-201`) returns `!per_thread` for
`ClockSpec::CpuEncoded`, so an ENCODED (dynamic, per-PID) per-thread CPU clock
gets `EOPNOTSUPP`. Linux disagrees, because the encoded clocks route through
`clock_posix_cpu`, which DOES have `.nsleep = posix_cpu_nsleep`
(`posix-cpu-timers.c:1711`):

| Clock | Linux | Here |
|---|---|---|
| static `CLOCK_THREAD_CPUTIME_ID` | EOPNOTSUPP (`clock_thread` has no `.nsleep`, `:1727-1731`) | EOPNOTSUPP — correct |
| static `CLOCK_PROCESS_CPUTIME_ID` | sleeps on process CPU time | wall-clock sleep — wrong, the 3a body |
| encoded per-thread naming SELF or pid 0 | **EINVAL** (`:1639-1642`) | EOPNOTSUPP — wrong |
| encoded per-thread naming ANOTHER thread | real CPU sleep | EOPNOTSUPP — wrong |

The EINVAL case is separable and is a pure admission rule; the other two need
the wake mechanism above. Fixing the admission ladder alone would let the
naming-another-thread case fall through to a sleep that does not yet exist, so
the ladder and the body must land TOGETHER.

## 16 3a landed — and the one case the clock spec cannot express

Implemented exactly as §15 designed: `Notify::Wake { tid }` on `PosixTimer`,
intercepted in `service_wake` before the signal-shaped `expire` path, so
`account_cpu_tick` — already running on the RUNNING task — releases the sleeper
through the existing `ttwu_deferred`. No new per-task state, no new IRQ path.

Residual divergence, found during implementation and NOT fixable without a
representation change: `classify_clock` maps the STATIC
`CLOCK_THREAD_CPUTIME_ID` to `CpuEncoded { pid: 0, per_thread: true }` — the
identical value a DYNAMIC per-thread clock naming pid 0 produces. Linux tells
them apart only by which `k_clock` table the id reaches: the static id lands on
`clock_thread` (no `.nsleep` -> EOPNOTSUPP, `posix-cpu-timers.c:1727-1731`),
the dynamic one on `clock_posix_cpu` (has `.nsleep` -> EINVAL for self,
`:1639-1642`). Resolved in favour of the static reading because that is the
reachable case; a dynamic per-thread clock naming pid 0 therefore reports
EOPNOTSUPP where Linux reports EINVAL. Closing it needs `ClockSpec` to carry
static-vs-dynamic provenance.

Still open on this path: `CpuMeasure::Sched` is `utime+stime` where Linux's
`CPUCLOCK_SCHED` is `task_sched_runtime()`; and a single-threaded process
sleeping on `CLOCK_PROCESS_CPUTIME_ID` blocks until signalled, which IS Linux's
behaviour (nothing advances the clock) but is worth knowing before anyone
reports it as a hang.

## 17 F752 — the untimed-family trap is gone, not signposted

B1447 could only make the dependency visible; F752 removes it. AF_VSOCK and
netlink now carry the SO_{RCV,SND}TIMEO fields Linux keeps on `sk`, so all four
sites pass a REAL deadline and `sock_intr_untimed_family_*` is deleted along
with the struct markers.

Linux never had a family-specific setsockopt for these: they are SOL_SOCKET
options handled by the generic `sock_setsockopt`, which is why
`vsock_connectible_recvmsg` (`af_vsock.c:2384`) / `_sendmsg` (`:2267`) and
`__skb_wait_for_more_packets` (`net/core/datagram.c:128`) can just read
`sock_rcvtimeo`/`sock_sndtimeo` back. Both handlers here REJECTED SOL_SOCKET
outright with ENOPROTOOPT, so `setsockopt(SO_RCVTIMEO)` on a vsock or netlink
socket failed — a plain conformance bug independent of the restart work.

The ns-to-deadline conversion now lives once in `sock_intr::deadline_from_timeo`
rather than once per family, so the `0 == MAX_SCHEDULE_TIMEOUT` convention
cannot drift.

Still open on this path: AF_VSOCK `getsockopt` does not report the two values
back (Linux's generic `sock_getsockopt` does); only the setsockopt side and the
wait sites are wired.

## 18 Guest differential — F753, and a campaign-wide caveat that was not real

### The mechanism exists in-tree. "Blocked on the images repo" is wrong.

F752 closed recording guest differentials as **impossible from a
kernel-repo lane**: `/bin/` probes come from the images repo (needs sudo),
and the only in-tree injection it found was `debugfs -w` into the rootfs,
a `metadata_csum` corruption hazard. That conclusion is in its merged
report and will be read as settled. **It is wrong, and every phase of this
campaign that carried "no guest exercise" as an unavoidable caveat was
accepting a limit that does not exist.**

The path is the one `af_packet_diff` already used. Three files constitute
it; copy them for any future lane:

| File | Role |
|---|---|
| `userspace/<probe>/` | glibc-ABI C, one `wdiff\|area\|test\|k=v` record per case |
| `tools/xtask/src/rootfs_disks/<probe>.rs` | per-arch cross-build + systemd oneshot injection, gated on an `OXIDE_*_SMOKE` env var so default builds are byte-identical |
| `tools/boot-smoke-<probe>.sh` | run the SAME binary on the host oracle, boot once, diff the record streams |

`debugfs -w` is used, but only against the staged `root-<arch>.img` build
artifact, never a mounted or in-use filesystem — which is what made it
hazardous in the case F752 was thinking of.

### Result — x86 guest vs host oracle, 29 vs 29 records, 15 DIVERGE / 14 match

Falsification gate `tools/wait-diff-selftest.sh`: 9 mutants, each asserted
to change the records it should and NO others. PASS.

| Probe | Oracle | oxide | |
|---|---|---|---|
| `sleep\|rel_norestart` | `EINTR` | `rc=0` | DIVERGE |
| `sleep\|rel_sarestart` | `EINTR` | `rc=0` | DIVERGE |
| `sleep\|abs_sarestart` | `EINTR` | `rc=0` (was `ENOSYS` on 2 earlier boots — UNSTABLE) | DIVERGE |
| `sleep\|stopcont_restart_block` | `rc=0 rem_written=1` | `rc=0 rem_written=0` | DIVERGE |
| `fd\|pipe_read_sarestart` | `ok payload=1` | `ok payload=1` | match |
| `fd\|pipe_read_norestart` | `eintr` | **`enosys`** | DIVERGE |
| `fd\|unix_recv_sarestart` | `ok payload=1` | `eintr` | DIVERGE |
| `fd\|unix_recv_norestart` | `eintr` | `eintr` | match |
| `fd\|unix_recv_timed_sarestart` | `eintr` | `eintr` | match |
| `fd\|tcp_recv_sarestart` | `ok payload=1` | `eintr` | DIVERGE |
| `fd\|tcp_recv_norestart` | `eintr` | `eintr` | match |
| `jobctl\|sigttin_stops_background` | `stopped=1` | `stopped=unknown` | DIVERGE |
| `jobctl\|read_resumes_after_fg` | `data rc=3` | `timeout` | DIVERGE |
| `cputime\|thread_cputime_nsleep` | `eopnotsupp` | `eopnotsupp` | match |
| `cputime\|single_thread_no_progress` | `eintr` | **`ok`** | DIVERGE |
| `cputime\|sibling_burn_completes` | `ok` | `ok` | match (weak — wall-clock also completes) |
| `mqueue\|sigkill_kills_blocked_receiver` | `signalled SIGKILL` | same | match |
| `mqueue\|recv_sarestart` | `ok payload=1` | `ok payload=1` | match |
| `mqueue\|recv_norestart` | `eintr` | **`enosys`** | DIVERGE |
| `lock\|flock_sarestart` | `ok` | `ok` | match |
| `lock\|flock_norestart` | `eintr` | **`enosys`** | DIVERGE |
| `lock\|setlkw_sarestart` | `ok` | `blocked` | DIVERGE |
| `lock\|setlkw_norestart` | `eintr` | **`enosys`** | DIVERGE |

Not covered: blocking `connect` (no deterministic arrangement — an
unreachable peer never completes, so the SA_RESTART arm would hang);
`syslog` (opt-in, needs CAP_SYSLOG + an EMPTY ring, reachable on the
oracle only by CONSUMING the host ring); `mq_timedsend` full-queue block;
PI futexes (`-ENOSYS`, §7). **aarch64 NOT RUN** — x86 only in this lane.

### D1 — every "must report EINTR" case returns ENOSYS. One bug, four subsystems.

`fd|pipe_read_norestart` was the discriminator and it is unambiguous:
`pipe_read_sarestart` RESUMES correctly with its payload, `sig=1` in every
record, so the interrupter (`setitimer`) is EXONERATED and the
syscall-return tail is implicated. Then the same shape appears in four
unrelated subsystems — pipe, mqueue, flock, F_SETLKW — every one of them
the no-`SA_RESTART` arm, every one returning **ENOSYS** where Linux
returns EINTR.

ENOSYS is what an INVALID SYSCALL NUMBER produces. The shape to check
first: the handler frame is built with the user PC rewound to re-execute
`syscall`/`svc` even on the `RestartAction::Eintr` arm, so `rt_sigreturn`
re-enters with the return value (`-EINTR` = -4) sitting in the
syscall-number register. `restart=true` works precisely because the number
register holds the real number there. NOT instrumented — narrowed suspect,
not proof. `syscall::restart::signal_restart_action` itself is correct and
hosted-tested; the defect is below it, in `dispatch_pending` /
`fs::sig_dispatch::deliver_with_info` / `hal_*` frame construction.

### D2 — F748 sockets do not restart

`unix_recv_sarestart` and `tcp_recv_sarestart` report EINTR where Linux
resumes and delivers the payload, while the `norestart` and timed
siblings match. That pattern says the socket sites return a REAL `-EINTR`
rather than `-ERESTARTSYS`, so the tail never sees a restart code — i.e.
F748's `sock_intr` conversion is not reaching these paths at runtime.
Note the timed case matching is NOT evidence of correctness: EINTR is the
right answer there for the wrong reason.

### D3 — F751 CPU-clock sleep is still a wall-clock sleep

`cputime|single_thread_no_progress` returns `ok` where Linux returns
`eintr`. A single-threaded process accrues no CPU while asleep, so nothing
can advance `CLOCK_PROCESS_CPUTIME_ID` and the sleep MUST NOT complete.
oxide completing it is exactly the `wallcpu` mutant shape — the pre-F751
behaviour. `sibling_burn_completes` matching is worthless as corroboration
because a wall-clock sleep completes there too.

### D4 — F749 tty job control does not resume after fg

`read_resumes_after_fg` times out; the backgrounded read never comes back
after `tcsetpgrp` + SIGCONT. This is F749's headline fix and its stated
motivation ("with EINTR it failed permanently instead of resuming after
`fg`"). `stopped=unknown` is collateral — the session leader was killed by
its own guard before it could report the SIGTTIN stop.

### D5 — fcntl(F_SETLKW) parks unkillably

`setlkw_sarestart` = `blocked`. Worse than the record shows: with the lock
probes running FIRST, the stall was not bounded by any in-probe guard —
the parent never reached its own `poll` timeout — so from userspace the
park looks unkillable, the class F745/F747 fixed for mqueue. That is why
`probe_locks` runs last.

### What PASSES, and is now actually verified

`mqueue` SIGKILL-on-parked-receiver (F745/F747 — the unkillable park is
genuinely gone), `mqueue|recv_sarestart`, `pipe_read_sarestart`,
`flock_sarestart`, `thread_cputime_nsleep` EOPNOTSUPP admission. Those are
five real confirmations that previously rested on reading alone.

### The correction the oracle forced

`nanosleep`/`clock_nanosleep` are **never** restarted by `SA_RESTART`
(`signal(7)`; they return `-ERESTART_RESTARTBLOCK`, which `handle_signal`
rewrites to `-EINTR` for any handler delivery). This lane was commissioned
on the opposite assumption. The oracle disagreed with the remembered claim
before it disagreed with the kernel — which is the argument for running
the real syscall rather than writing down what it ought to do. Detail in
`userspace/wait_diff/README.md` §2, where someone editing a sleep case
will read it.

### Attribution — the campaign's code is correct, the behaviour got worse

`syscall::restart::signal_restart_action` is Linux-correct and
hosted-tested. The `sig=1` in every diverging record proves a handler ran,
yet the outcomes are exactly the **no-handler** arm of
`arch_do_signal_or_restart`: `RestartBlockCall` -> `rc=0`, `RestartSame` ->
`ENOSYS`. One mechanism fits all four, and the two failure shapes
partition exactly along those two actions. Suspect the `handler_ran`
wiring in `dispatch/core.rs` or the frame rewrite in
`hal_*::restart_ignored_syscall`. NOT instrumented — hypothesis, not proof.

Pre-F750 `flock` returned a flat `EINTR` and never entered the restart
tail. F750 correctly changed it to `-ERESTARTSYS`, which routes it into
that tail — so it went from EINTR (correct) to ENOSYS (garbage). A
pre-existing latent defect ACTIVATED by the campaign. The fix belongs in
the tail, not in a revert of F750. Anyone reading "F750: DONE" today is
reading a claim that is not true at runtime.

Each divergence gets its own lane with the probe record as reproducer.
None is fixed here: if the return-tail defect is real it touches every
restartable syscall and deserves its own boot verification, not a fix
bolted onto the harness that found it.

### aarch64 — RUN, and the return-tail defect is ARCH-DIVERGENT

Full 29 records collected (`target/smoke/wait-diff/arm-*`). Same probe,
same oracle. The campaign-level divergences (D2 sockets, D3 CPU sleep, D4
tty, D5 F_SETLKW) reproduce IDENTICALLY on both arches — so those are
arch-independent. The D1 return-tail family does NOT:

| Probe | Oracle | x86 | aarch64 |
|---|---|---|---|
| `fd\|pipe_read_norestart` | `eintr` | `enosys` | **`ok payload=1`** |
| `lock\|flock_norestart` | `eintr` | `enosys` | `other` |
| `lock\|setlkw_norestart` | `eintr` | `enosys` | `other` |
| `mqueue\|recv_norestart` | `eintr` | `enosys` | `other` |
| `sleep\|abs_sarestart` | `eintr` | `rc=0` / `enosys` (unstable) | **`einval`** |

aarch64 `pipe_read_norestart` returning `ok payload=1` is the sharpest
single record in the lane: without `SA_RESTART` the read RESTARTED and
delivered its payload, which is the exact opposite of the required
behaviour and a different wrong answer from x86's ENOSYS. Whatever the
tail does with `RestartAction::Eintr`, it does something different per
arch — consistent with the suspect being the per-arch signal-frame
construction (`hal_x86_64` / `hal_aarch64` + `fs::sig_dispatch`), not the
shared decision module.

Harness limitation: `err_class` collapses anything outside
{EINTR,ENOSYS,EOPNOTSUPP,EINVAL} to `other`, so the aarch64 errno on three
records is unidentified. Widening it to carry the raw errno is a one-line
follow-up and would sharpen the aarch64 half of D1.
## 19 B1449 — F748 never reached the shim, and the six wait loops it missed

D2 (§18) is confirmed and its cause is narrower than "the conversion is not
reaching these paths": F748 migrated the wait loops that live in the WORK-FN
crates (`net`, `netlink`, `socket`). It did not touch the wait loops that live
in the ABI shim, because none of `crates/kernel/syscalls/src/**` compiles
hosted, so no grep-by-test and no hosted suite could see them. `recv(2)` on an
AF_UNIX or TCP socket routes to those shim loops, never to the migrated ones:

    sys_recvfrom -> recvmsg::lookup -> recvmsg::recv (`recvmsg/dispatch.rs:60-70`)
      SockKind::Unix*  -> `unix_recv::recvmsg` -> `wait_nonblock_after`
      SockKind::TcpConn -> `recvmsg::inet::tcp_with_copy_pinned`

Both ended their interrupted wait with a literal `Errno::Eintr`. Eight sites
in all, every one a blocking socket wait Linux ends with `sock_intr_errno`:

| Site | Linux |
|---|---|
| `unix_recv.rs:24` (stream + seqpacket + dgram) | `af_unix.c:2997-2999`, `datagram.c:122-128` |
| `recvmsg/inet.rs:228` TCP stream | `tcp.c:2783-2786` |
| `recvmsg/inet.rs:264` TCP urgent | same rule |
| `recvmsg/netlink.rs:33` | `datagram.c:128` via `skb_recv_datagram` |
| `recvmsg/vsock.rs:101` stream | `af_vsock.c:2383-2385` |
| `recvmsg/vsock.rs:185` seqpacket | same |
| `043_accept.rs:54` TCP/AF_UNIX accept | `inet_connection_sock.c:635-637` |
| `043_accept.rs:151` AF_VSOCK accept | `af_vsock.c:1903-1905` |

The decision is `net_errno::{sock_intr_errno, recv_interrupted}` — non-gated,
hosted-tested, one owner; `recv_interrupted` also carries `tcp_recvmsg_locked`'s
partial-transfer rule (`tcp.c:2735-2742`) so the two stream sites cannot drift.
The shim source-text guard lives in `net_common.rs` because the loops themselves
cannot be compiled hosted; it counts the waits so a new one cannot be added
without the rule.

### The aarch64 `unix_recv_sarestart` pass is not a working restart

Post-B1448 the aarch64 record reads `ok payload=1` while x86 reads `eintr`,
which invites reading AF_UNIX as arch-split. It cannot be: `-EINTR` is not an
ERESTART* sentinel, so `signal_restart_action` returns `RestartAction::None` for
it under EVERY handler/SA_RESTART combination
(`net_errno::a_flat_eintr_from_a_receive_wait_can_never_restart_on_any_arch`),
and `unix_recv.rs` is arch-neutral. An interrupted AF_UNIX recv therefore could
not resume on either arch. The aarch64 `ok` is a NOT-INTERRUPTED run — the
SIGALRM landed after the peer's 600 ms write, so the payload returned and the
signal was delivered at the syscall tail. Re-run that record N times before
treating either arch's value as stable.

### Found while reading, NOT closed here

- `tcp_recv_urg` (`net/ipv4/tcp.c:1513-1519`) NEVER blocks — "this call should
  never block, independent of the blocking state of the socket" — and returns
  `-EAGAIN` when no urgent byte is ready. `recvmsg/inet.rs` `tcp_oob_with_copy`
  parks instead. Own lane: it is a blocking-policy defect, and changing it moves
  the already-matching `af_packet_diff|recvfrom|tcp_oob` row.
- SO_RCVTIMEO is read for the interrupt verdict but NOT enforced on the park for
  netlink (`netlink/src/receive.rs` `arm_receive_wait`, both the `read(2)` and
  `recvmsg(2)` paths) and AF_VSOCK (`recvmsg/vsock.rs` passes `0` to
  `arm_recv_wait` / `arm_seqpacket_recv_wait`; `043_accept.rs` passes `0` to
  `arm_accept_wait_exact`). A timed recv on those families blocks forever
  instead of reporting EAGAIN. Pre-existing, predates F752, own lane.
## 19 B1450 — 3a's wake mechanism was sound, its clock resolution never ran

§16 reported 3a landed. The guest differential (`cputime|
single_thread_no_progress`: host `eintr`, oxide `ok` on BOTH arches) says it
never took effect. It is not the wake mechanism: `Notify::Wake` /
`service_wake` / `account_cpu_tick` are all correct as designed. The sleep
never reached them.

`classify_clock` decodes the static `CLOCK_PROCESS_CPUTIME_ID` to
`ClockSpec::CpuEncoded { pid: 0, per_thread: false, .. }` — an UNRESOLVED
encoding. `timers::clock::now_ns` has no arm for the encoded form; it samples
only the resolved `ClockSpec::Cpu` and returns `None` for everything else
(`clock.rs:99-108`). `cpu_nanosleep::body` passed that encoding straight to
`now_ns`, so its very first statement — `let Some(now) = … else { return 0 }`
— returned "no CPU time owed" and `230_clock_nanosleep` mapped that to
`CpuSleepExit::Completed` → rc 0. The syscall returned IMMEDIATELY, not after
300 ms: worse than the wall-clock sleep the row was read as.

Linux resolves exactly once, in `posix_cpu_timer_create`
(`posix-cpu-timers.c:386-411`): `pid_for_clock(new_timer->it_clock, false)`
stores a `struct pid` on the timer and every later sample reads THAT task.
`do_cpu_nanosleep` runs the same create for its stack timer (`:1552`). The
equivalent resolver already existed here — `timers::clock::resolve_clock`,
which `clock_gettime` uses — and was simply not called on the sleep path.

Second-order consequence of the same omission: `runtime::cpu_clock_runs_for`
matches `ClockSpec::Cpu(_)` only, so even had the arm survived, an encoded
domain would never have been serviced by `account_cpu_tick`. Resolving at arm
time fixes both, and the wall-timer exclusion now shares one predicate
(`is_cpu_clock`) instead of an open-coded `matches!`.

Third: slot 230 gated admission on `clock_id_known` — futex's "is this a
static `posix_clocks[]` slot" predicate — where Linux gates on
`clockid_to_kclock(which_clock) != NULL` (`posix-timers.c:1388-1391`). Every
negative `clock_getcpuclockid(2)` encoding was therefore EINVAL'd before the
`.nsleep` table was consulted, which is why §15's admission table was never
observably fixed and why `perthread_names_self`'s EINVAL was dead code. With
the gate corrected, that rule is reachable — and had to become
namespace-correct: Linux compares `CPUCLOCK_PID` against `task_pid_vnr`, so
`names_self` resolves the encoded pid before comparing it to the caller.

Still open, and NOT the same edit: `CpuMeasure::Sched` is `utime+stime`
(`clock.rs:78-96`) where Linux's `CPUCLOCK_SCHED` is `task_sched_runtime()`.
Closing it needs (a) a `sched_ns` aggregate on `ThreadGroup` — `cpu_now_ns`
runs from `account_cpu_tick` in hard-IRQ context, so a registry walk over live
threads is forbidden (`06§3.1`, pinned by
`timing::hardirq_tick_paths_perform_no_registry_lookup`); (b) a charge site in
`update_curr` (`live/schedule/switch.rs:117-131`); (c) that charge moved above
`update_curr`'s `SchedClass::Normal` early-return, or an RT thread's process
clock stops advancing entirely — which also means moving the `exec_start_ns`
re-stamp and changing what `balance.rs:172` reads for non-CFS tasks; and (d)
Linux's on-demand `task_sched_runtime()` delta, since `sum_exec_runtime_ns`
only advances at `schedule()` entry. That is a scheduler-accounting change on
the hottest path in the kernel, not a clock_nanosleep change, and it wants its
own lane and its own boot verification.
