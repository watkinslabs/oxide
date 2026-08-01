use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};

pub mod child_acct;
pub mod group_acct;
pub mod shared_signal;

use crate::pid::PidIdentity;
use crate::task::PosixTimer;
use crate::Task;

/// `SIGNAL_GROUP_EXIT` clear. Every real internal exit status is non-negative
/// (`crate::exit::status`), so no group death can spell this value.
const GROUP_EXIT_UNSET: i32 = i32::MIN;

/// Result of retiring one task from its thread group after context handoff.
pub enum ExitDisposition {
    AlreadyRetired,
    ReleasedThread,
    DeferredLeader,
    WaitableLeader(Arc<Task>),
}

/// Stable thread-group owner shared by all member tasks.
pub struct ThreadGroup {
    leader: Arc<PidIdentity>,
    /// Process-wide POSIX timers (`timer_create(2)`). Linux keeps these in
    /// `signal_struct`, shared by the whole thread group — and so do we now.
    ///
    /// They previously lived on the *leader's* `Task` and every access resolved
    /// the leader through the global task registry: `timer_owner` →
    /// `registry::lookup` → `REG.lock()` plus an O(N) scan. Two hard-IRQ paths
    /// did that on EVERY tick (`deadline::rearm_local`, `cpustat::charge_current_tick`)
    /// for any thread that is not its group leader — i.e. constantly. `REG` is a
    /// plain lock held by fork/exit/execve with IRQs enabled, so the tick could
    /// preempt a holder and wedge that CPU permanently (`06§3.1`).
    ///
    /// Every member already holds an `Arc<ThreadGroup>`, so reaching them here
    /// is O(1) with no lock and no lookup — the same directness Linux gets from
    /// `task->signal`.
    ///
    /// Mutation is serialized by `timers::backend`'s STATE lock, exactly as it
    /// was when the array lived on the leader.
    ///
    /// Grows on demand (`timers::slots`): Linux allocates each `k_itimer` from
    /// its own slab with no per-process ceiling, so a fixed array would EAGAIN
    /// a process that legitimately holds more timers than the initial working
    /// set.
    pub posix_timers: UnsafeCell<Vec<PosixTimer>>,
    /// Process-wide resource limits (Linux `signal_struct.rlim`). 16 slots
    /// indexed by `RLIMIT_*`, each `(cur, max)`.
    ///
    /// Linux keeps rlimits on `signal_struct`, so every thread of a process
    /// observes ONE table: `setrlimit(2)` in one thread is immediately visible
    /// to its siblings, and `RLIMIT_NOFILE`/`RLIMIT_STACK` are properties of the
    /// process, not of whichever thread happened to raise them. Holding them
    /// per-`Task` gave each `CLONE_THREAD` sibling a private copy — a split
    /// source of truth that made `getrlimit(2)` answer stale after a sibling's
    /// `setrlimit(2)`.
    ///
    /// `fork(2)` gets a fresh `ThreadGroup` and copies the parent's table
    /// (Linux `copy_signal`); `CLONE_THREAD` shares this one.
    ///
    /// Spinlock-protected: `prlimit64(2)` and `sched_setattr(2)` read/write an
    /// ARBITRARY target's limits from the caller's own CPU.
    pub rlimits: Spinlock<[(u64, u64); crate::rlimit::rlim::COUNT], TaskListClass>,
    /// Linux `signal_struct::timer_create_restore_ids`
    /// (`prctl(PR_TIMER_CREATE_RESTORE_IDS)`). While set, `timer_create(2)`
    /// reads its `timer_t __user *` OUT parameter as an IN parameter — the id
    /// the caller wants the new timer to receive — which is how
    /// checkpoint/restore recreates a process' timers under their old ids.
    /// Process-wide, and reset to 0 by execve exactly as Linux resets it.
    pub timer_create_restore_ids: AtomicBool,
    /// POSIX process-group id (Linux `PIDTYPE_PGID` on `task->signal`). Every
    /// thread of a process is in ONE process group — `setpgid(2)` moves the
    /// whole process, never a single thread — so this is process-wide state,
    /// exactly like the `posix_timers` above. It previously lived on `Task`
    /// and was byte-copied per thread at `CLONE_THREAD`, which made a threaded
    /// process's `setpgid` visible only to the thread that ran it: `kill(-pgid)`
    /// and tty job control then reached a subset of the process.
    pgid: AtomicU32,
    /// POSIX session id (Linux `PIDTYPE_SID` on `task->signal`). Process-wide
    /// for the same reason as `pgid`.
    sid: AtomicU32,
    /// Linux `signal_struct::leader` — set exactly once by `setsid(2)`. Gates
    /// the `setsid` EPERM re-entry check and the `setpgid` "target is a session
    /// leader" EPERM.
    session_leader: AtomicBool,
    /// Linux `signal_struct::is_child_subreaper` — `prctl(PR_SET_CHILD_SUBREAPER)`.
    /// Process-wide, not per-thread: any thread may set it and every thread of
    /// the process is then a candidate reaper. `find_new_reaper` walks the
    /// ancestor chain looking for this flag before falling back to init, which
    /// is what makes `systemd --user` collect its session's orphans instead of
    /// leaking them to PID 1.
    is_child_subreaper: AtomicBool,
    state: Spinlock<ThreadGroupState, TaskListClass>,
    /// Linux `signal_struct::group_exit_code` and its `SIGNAL_GROUP_EXIT`
    /// flag fused into one word: the status EVERY thread of this group
    /// reports, in `crate::exit::status`' internal encoding, whatever signal
    /// individually cut each thread down. [`GROUP_EXIT_UNSET`] stands for the
    /// flag being clear; every real status is non-negative, so the sentinel
    /// cannot collide.
    ///
    /// One word rather than a flag/value pair so the latch is a single
    /// `compare_exchange` — a loser can never transiently publish its own
    /// code over the winner's. Lock-free rather than a `state` field because
    /// the reap path reads it while holding the `ZOMBIES` list, another
    /// `TaskList`-class lock (`06§3.6` forbids that nesting).
    group_exit_code: AtomicI32,
    /// Linux `signal_struct::group_stop_count` — how many threads of this
    /// process still owe the group stop in progress a stop. Seeded when the
    /// stop is initiated and decremented by each thread as it parks; the one
    /// that drives it to zero completes the stop and is the ONE that reports
    /// `CLD_STOPPED` to the real parent. Without the counter every thread of a
    /// threaded process reported its own stop, so a shell saw N `SIGCHLD`s for
    /// one `^Z`.
    group_stop_count: AtomicU32,
    /// Linux `signal_struct::flags & SIGNAL_STOP_STOPPED` — the group stop has
    /// completed and been reported. A thread joining an already-completed stop
    /// owes nobody a second `CLD_STOPPED`; the latch drops on SIGCONT.
    stop_stopped: AtomicBool,
    /// Linux `signal_struct::shared_pending.signal` — the PROCESS-directed
    /// pending bitmap, the set `kill(2)`/`kill_pgrp`/`sigqueue(3)` post into
    /// and that ANY thread of the group may dequeue from. See
    /// `thread_group/shared_signal.rs` for why it cannot live on the leader's
    /// `Task`.
    shared_pending: AtomicU64,
    /// Linux `signal_struct::shared_pending.list` — the queued `siginfo_t`
    /// records behind `shared_pending`, same per-signal shape and depth policy
    /// as the thread-private set (`crate::sigqueue::SigQueues`).
    shared_sigqueue: crate::sigqueue::SigQueues,
    /// Linux `sighand_struct::signalfd_wqh` — the ONE readiness source every
    /// `signalfd` in this process waits on. Per PROCESS, not per thread,
    /// because a signalfd reads `private | shared`: an edge raised on one
    /// thread's private send must reach a sibling's poller, and a
    /// process-directed send has no thread of its own to raise it on.
    signalfd_poll: alloc::sync::Arc<vfs::PollSubscribers>,
    /// Linux `signal_struct::tty` — the CONTROLLING TERMINAL, POSIX
    /// §11.1.3. A controlling terminal belongs to the process (and through
    /// its session, to every process in that session): `setsid(2)` drops it
    /// process-wide via `proc_clear_tty(group_leader)`, `TIOCSCTTY` claims it
    /// process-wide, and a hangup revokes it process-wide. Holding it
    /// per-`Task` gave each `CLONE_THREAD` sibling a private copy — the same
    /// split source of truth `pgid`/`sid` above were moved here to fix:
    /// `setsid` in one thread left its siblings still pointing at the old
    /// terminal, and `/dev/tty` then resolved differently per thread of one
    /// process.
    ///
    /// Spinlock rather than the old `UnsafeCell`: the hangup walk clears an
    /// ARBITRARY process's terminal from whichever CPU processed the hangup,
    /// so the single-mutator argument that held for a per-task cell does not
    /// hold for shared process state.
    ctty: Spinlock<Option<vfs::InodeRef>, TaskListClass>,
    /// Linux `signal_struct::tty_old_pgrp`: the foreground process group this
    /// session's terminal had at the moment it was hung up under us, 0 when
    /// none was saved. Recorded for session LEADERS only, by the hangup walk.
    /// The one reader is a leader's exit with no controlling terminal left,
    /// which owes that group SIGHUP+SIGCONT — without it a job stopped at the
    /// instant of a carrier drop stays stopped with nothing able to resume it.
    tty_old_pgrp: AtomicU32,
    user_ns: AtomicU64,
    system_ns: AtomicU64,
    /// Linux `signal_struct`'s `c*` counters — every reaped child's resource
    /// use. Process-wide: whichever thread reaps a child, all its siblings'
    /// `getrusage(RUSAGE_CHILDREN)` / `times(2)` must see the cost.
    child_acct: child_acct::ChildAcct,
    /// Linux `signal_struct`'s own-process fault / block-I/O / context-switch
    /// counters — the `RUSAGE_SELF` half that is not CPU time.
    group_acct: group_acct::GroupAcct,
}

struct ThreadGroupState {
    live: u32,
    pending_leader: Option<Arc<Task>>,
}

// SAFETY: the only interior-mutable field is `posix_timers`, whose every access
// is serialized by `timers::backend`'s STATE lock — the same discipline that
// applied when the array lived on `Task` (which is `Sync` for the same reason).
unsafe impl Sync for ThreadGroup {}

impl ThreadGroup {
    /// Create a one-task group around its leader PID identity. # C: O(1)
    pub fn new(leader: Arc<PidIdentity>) -> Self {
        let seed = leader.tid;
        Self {
            leader,
            posix_timers: UnsafeCell::new(alloc::vec![PosixTimer::default(); PosixTimer::SLOTS]),
            rlimits: Spinlock::new(crate::rlimit::DEFAULT_RLIMITS),
            timer_create_restore_ids: AtomicBool::new(false),
            pgid: AtomicU32::new(seed),
            sid:  AtomicU32::new(seed),
            session_leader: AtomicBool::new(false),
            is_child_subreaper: AtomicBool::new(false),
            state: Spinlock::new(ThreadGroupState { live: 1, pending_leader: None }),
            group_exit_code: AtomicI32::new(GROUP_EXIT_UNSET),
            group_stop_count: AtomicU32::new(0),
            stop_stopped: AtomicBool::new(false),
            shared_pending: AtomicU64::new(0),
            shared_sigqueue: crate::sigqueue::new_queues(),
            signalfd_poll: alloc::sync::Arc::new(vfs::PollSubscribers::new()),
            ctty: Spinlock::new(None),
            tty_old_pgrp: AtomicU32::new(0),
            user_ns: AtomicU64::new(0),
            system_ns: AtomicU64::new(0),
            child_acct: child_acct::ChildAcct::new(),
            group_acct: group_acct::GroupAcct::new(),
        }
    }

    /// The process' `signalfd` readiness source, handed to every thread's
    /// `SignalPending` so both pending sets raise edges on one list. # C: O(1)
    pub fn signalfd_poll(&self) -> alloc::sync::Arc<vfs::PollSubscribers> {
        alloc::sync::Arc::clone(&self.signalfd_poll)
    }

    /// Accumulated resource use of every child this process reaped. # C: O(1)
    pub fn child_acct(&self) -> &child_acct::ChildAcct { &self.child_acct }

    /// This process's own fault / block-I/O / context-switch counters,
    /// covering live and already-exited threads alike. # C: O(1)
    pub fn group_acct(&self) -> &group_acct::GroupAcct { &self.group_acct }

    /// Process group id shared by every thread of this process. # C: O(1)
    pub fn pgid(&self) -> u32 { self.pgid.load(Ordering::Acquire) }

    /// Move the whole process into process group `pgid`. # C: O(1)
    pub fn set_pgid(&self, pgid: u32) { self.pgid.store(pgid, Ordering::Release); }

    /// Session id shared by every thread of this process. # C: O(1)
    pub fn sid(&self) -> u32 { self.sid.load(Ordering::Acquire) }

    /// Move the whole process into session `sid`. # C: O(1)
    pub fn set_sid(&self, sid: u32) { self.sid.store(sid, Ordering::Release); }

    /// Linux `signal_struct::leader`. # C: O(1)
    pub fn is_session_leader(&self) -> bool { self.session_leader.load(Ordering::Acquire) }

    /// Latch session leadership; `false` when it was already latched, which is
    /// `setsid(2)`'s EPERM. # C: O(1)
    pub fn claim_session_leader(&self) -> bool {
        !self.session_leader.swap(true, Ordering::AcqRel)
    }

    /// The group leader's `Task`, straight off the group's own PID identity —
    /// O(1), no registry lock and no scan. # C: O(1)
    pub fn leader_task(&self) -> Option<Arc<Task>> { self.leader.task() }

    /// Linux `task_tgid()`: the group's pinned pid identity, which outlives the
    /// leader `Task` and is what a peer-credential snapshot must retain to name
    /// the process after its numeric pid is recycled. # C: O(1)
    pub fn leader_pid(&self) -> Arc<PidIdentity> { self.leader.clone() }

    /// `prctl(PR_GET_CHILD_SUBREAPER)`. # C: O(1)
    pub fn is_child_subreaper(&self) -> bool { self.is_child_subreaper.load(Ordering::Acquire) }

    /// `prctl(PR_SET_CHILD_SUBREAPER, arg2)` — Linux
    /// `me->signal->is_child_subreaper = !!arg2`. # C: O(1)
    pub fn set_child_subreaper(&self, on: bool) {
        self.is_child_subreaper.store(on, Ordering::Release);
    }

    /// The process's controlling terminal (Linux `signal_struct::tty`).
    /// # C: O(1); # Lk: TaskList
    pub fn ctty(&self) -> Option<vfs::InodeRef> { self.ctty.lock().clone() }

    /// Inode number of the controlling terminal, without cloning the
    /// reference — the shape every "do I own THIS tty?" test wants.
    /// # C: O(1); # Lk: TaskList
    pub fn ctty_ino(&self) -> Option<u64> { self.ctty.lock().as_ref().map(|i| i.ino()) }

    /// Install or drop the process's controlling terminal. The displaced
    /// reference is released AFTER the lock, so an inode teardown never runs
    /// underneath it. # C: O(1); # Lk: TaskList
    pub fn set_ctty(&self, tty: Option<vfs::InodeRef>) {
        let previous = core::mem::replace(&mut *self.ctty.lock(), tty);
        drop(previous);
    }

    /// The foreground group saved when this session's terminal was hung up
    /// under it (Linux `signal_struct::tty_old_pgrp`), 0 when none.
    /// # C: O(1)
    pub fn tty_old_pgrp(&self) -> u32 { self.tty_old_pgrp.load(Ordering::Acquire) }

    /// Record (or, with 0, forget) the saved foreground group. # C: O(1)
    pub fn set_tty_old_pgrp(&self, pgrp: u32) {
        self.tty_old_pgrp.store(pgrp, Ordering::Release);
    }

    /// Commit one fully initialized clone-thread member. # C: O(1)
    pub fn commit_member(&self) {
        self.state.lock().live += 1;
    }

    /// Whether exactly one live task remains in this thread group. # C: O(1)
    pub fn is_single_member(&self) -> bool { self.state.lock().live == 1 }

    /// Live members not yet retired by [`Self::finish_exit`]. A task inside
    /// its own `do_exit` still counts itself, so `1` there means "I am the
    /// last"; after retirement `0` is Linux's `thread_group_empty`.
    /// # C: O(1)
    pub fn live_count(&self) -> u32 { self.state.lock().live }

    /// Join the group stop in progress, initiating it when this is the first
    /// thread to arrive.
    ///
    /// The rule itself is the ungated `jobctl::participate_group_stop`; this
    /// method only owns the counter's storage and its seeding — the first
    /// thread to arrive sizes the stop by the group's live membership.
    /// # C: O(1)
    pub fn join_group_stop(&self, jobctl: u64) -> crate::jobctl::GroupStopStep {
        let count = match self.group_stop_count.load(Ordering::Acquire) {
            0 => { let n = self.live_count().max(1); self.group_stop_count.store(n, Ordering::Release); n }
            n => n,
        };
        let step = crate::jobctl::participate_group_stop(
            jobctl, count, self.stop_stopped.load(Ordering::Acquire));
        self.group_stop_count.store(step.count, Ordering::Release);
        // `signal_set_stop_flags(sig, SIGNAL_STOP_STOPPED)` — latched by the
        // thread that completes the stop, so a later joiner reports nothing.
        if step.completed { self.stop_stopped.store(true, Ordering::Release); }
        step
    }

    /// A SIGCONT (or a group exit) ends the stop: the tally restarts and the
    /// `SIGNAL_STOP_STOPPED` latch drops, so the next `^Z` is a fresh group
    /// stop that reports again. # C: O(1)
    pub fn end_group_stop(&self) {
        self.group_stop_count.store(0, Ordering::Release);
        self.stop_stopped.store(false, Ordering::Release);
    }

    /// Threads of this process that still owe the group stop a stop. # C: O(1)
    pub fn group_stop_count(&self) -> u32 { self.group_stop_count.load(Ordering::Acquire) }

    /// Linux `wait_task_zombie`'s `(signal->flags & SIGNAL_GROUP_EXIT) ?
    /// signal->group_exit_code : ...` guard. # C: O(1)
    pub fn group_exit_status(&self) -> Option<i32> {
        match self.group_exit_code.load(Ordering::Acquire) {
            GROUP_EXIT_UNSET => None,
            status           => Some(status),
        }
    }

    /// Linux `do_group_exit`: latch `group_exit_code` + `SIGNAL_GROUP_EXIT`,
    /// and report whether THIS caller won the latch and therefore owes
    /// `zap_other_threads`. A loser inherits the winner's status — which is
    /// what makes `exit_group(N)` from a non-leader report `N` for the whole
    /// process instead of the SIGKILL that felled the leader.
    /// # C: O(1)
    pub fn group_exit(&self, requested: i32) -> crate::exit::group::GroupExit {
        match self.group_exit_code.compare_exchange(
            GROUP_EXIT_UNSET, requested, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_)      => crate::exit::group::arbitrate(None, requested),
            Err(winner) => crate::exit::group::arbitrate(Some(winner), requested),
        }
    }

    /// Linux `synchronize_group_exit`: the LAST thread of a group publishes
    /// its own status when nothing latched one first, so a plain `exit(2)` by
    /// the final thread still reaches the parent through `group_exit_code`.
    /// A non-final thread's plain `exit(2)` latches nothing — its group
    /// survives it.
    /// # C: O(1)
    pub fn latch_final_exit(&self, status: i32) {
        if crate::exit::group::final_thread_latch(
            self.group_exit_status(), self.is_single_member(), status).is_none() { return; }
        let _ = self.group_exit_code.compare_exchange(
            GROUP_EXIT_UNSET, status, Ordering::AcqRel, Ordering::Acquire);
    }

    /// `zap_pid_ns_processes`' closing `current->signal->group_exit_code =
    /// pid_ns->reboot` (`kernel/pid_namespace.c:278-279`) — a PLAIN store, not
    /// a latch: it deliberately overwrites the SIGKILL status the namespace
    /// teardown already published, so the supervisor outside sees the reboot
    /// request instead of the kill that carried it out.
    /// # C: O(1)
    pub fn force_group_exit_code(&self, status: i32) {
        self.group_exit_code.store(status, Ordering::Release);
    }

    /// Charge aggregate process CPU time from the per-CPU accounting tick.
    /// # C: O(1)
    /// # Ctx: timer IRQ
    pub fn charge_cpu(&self, user: bool, delta_ns: u64) {
        if user { self.user_ns.fetch_add(delta_ns, Ordering::Relaxed); }
        else { self.system_ns.fetch_add(delta_ns, Ordering::Relaxed); }
    }

    /// Aggregate process CPU time without walking the thread registry. # C: O(1)
    pub fn cpu_sample(&self) -> (u64, u64) {
        (self.user_ns.load(Ordering::Acquire), self.system_ns.load(Ordering::Acquire))
    }

    /// Retire a switched-out task exactly once and delay an early leader until
    /// the final sibling exits. # C: O(N_subscribers)
    pub fn finish_exit(&self, task: Arc<Task>) -> ExitDisposition {
        if !task.pid.claim_exit_retirement() {
            return ExitDisposition::AlreadyRetired;
        }
        if task.pid.is_group_leader() {
            let waitable = {
                let mut state = self.state.lock();
                state.live -= 1;
                if state.live == 0 {
                    true
                } else {
                    state.pending_leader = Some(Arc::clone(&task));
                    false
                }
            };
            if waitable {
                self.leader.publish_group_exit();
                ExitDisposition::WaitableLeader(task)
            } else {
                ExitDisposition::DeferredLeader
            }
        } else {
            crate::registry::mark_reaped(&task);
            let pending_leader = {
                let mut state = self.state.lock();
                state.live -= 1;
                if state.live == 0 { state.pending_leader.take() } else { None }
            };
            if let Some(leader) = pending_leader {
                self.leader.publish_group_exit();
                ExitDisposition::WaitableLeader(leader)
            } else {
                ExitDisposition::ReleasedThread
            }
        }
    }
}
