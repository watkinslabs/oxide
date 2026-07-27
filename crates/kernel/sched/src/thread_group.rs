use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};

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
    user_ns: AtomicU64,
    system_ns: AtomicU64,
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
            pgid: AtomicU32::new(seed),
            sid:  AtomicU32::new(seed),
            session_leader: AtomicBool::new(false),
            is_child_subreaper: AtomicBool::new(false),
            state: Spinlock::new(ThreadGroupState { live: 1, pending_leader: None }),
            group_exit_code: AtomicI32::new(GROUP_EXIT_UNSET),
            user_ns: AtomicU64::new(0),
            system_ns: AtomicU64::new(0),
        }
    }

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
    /// O(1), no registry lock and no scan. Process-DIRECTED signals land on
    /// the leader's pending set in this kernel (`kill(2)` resolves a tgid to
    /// its leader), so this is where `signal_struct::shared_pending` lives.
    /// # C: O(1)
    pub fn leader_task(&self) -> Option<Arc<Task>> { self.leader.task() }

    /// `prctl(PR_GET_CHILD_SUBREAPER)`. # C: O(1)
    pub fn is_child_subreaper(&self) -> bool { self.is_child_subreaper.load(Ordering::Acquire) }

    /// `prctl(PR_SET_CHILD_SUBREAPER, arg2)` — Linux
    /// `me->signal->is_child_subreaper = !!arg2`. # C: O(1)
    pub fn set_child_subreaper(&self, on: bool) {
        self.is_child_subreaper.store(on, Ordering::Release);
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
