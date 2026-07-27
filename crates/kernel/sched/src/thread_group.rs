use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};

use crate::pid::PidIdentity;
use crate::task::PosixTimer;
use crate::Task;

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
    pub posix_timers: UnsafeCell<[PosixTimer; PosixTimer::SLOTS]>,
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
    state: Spinlock<ThreadGroupState, TaskListClass>,
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
            posix_timers: UnsafeCell::new([PosixTimer::default(); PosixTimer::SLOTS]),
            pgid: AtomicU32::new(seed),
            sid:  AtomicU32::new(seed),
            session_leader: AtomicBool::new(false),
            state: Spinlock::new(ThreadGroupState { live: 1, pending_leader: None }),
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

    /// Commit one fully initialized clone-thread member. # C: O(1)
    pub fn commit_member(&self) {
        self.state.lock().live += 1;
    }

    /// Whether exactly one live task remains in this thread group. # C: O(1)
    pub fn is_single_member(&self) -> bool { self.state.lock().live == 1 }

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
