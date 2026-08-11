// Generic FIFO wait list — companion to the per-subsystem WAITERS
// pattern in `zombies.rs`. Subsystems that need blocking semantics
// (SysV sem/msg, POSIX MQ, futex) instantiate one `WaitList` per
// resource and call `park()` to sleep, `wake_one()` / `wake_all()`
// from the corresponding wake site.
//
// Lock-ordering contract:
//   - Caller holds the resource lock (e.g. SemSet.vals) when
//     calling park(); park() acquires the wait list's internal
//     lock briefly to push, then returns. Caller drops resource
//     lock then calls schedule().
//   - Wakers (commit path) drop the resource lock BEFORE calling
//     wake_one/wake_all so the wait list lock is never nested
//     under the resource lock from the publisher side.
//
// This is the standard "lock-resource → push-to-wait → drop-
// resource → schedule" pattern. Wakeups can race with park
// without losing wake events because publishers always wake
// AFTER mutating the resource: a waiter that acquired the
// resource lock and saw the unmet condition will be visible on
// the wait list before the publisher can wake (publisher needs
// the resource lock to mutate, which the waiter already holds
// when pushing to the list).


use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
#[cfg(feature = "debug-desktop")]
use core::sync::atomic::AtomicU32;

use crate::{Task, TaskState};
use sync::{Spinlock, TaskList as WaitClass};

/// Bounded, feature-gated ledger for compositor deadline parks.  Retaining the
/// publication point makes a missed deadline wake distinguishable from an
/// absent timerfd/epoll registration without perturbing normal scheduling.
#[cfg(feature = "debug-desktop")]
static MUTTER_DEADLINE_PARK_TRACE_REMAINING: AtomicU32 = AtomicU32::new(64);

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
macro_rules! waiters_lock {
    ($list:expr) => { $list.waiters.lock_irqsave::<hal_x86_64::X86IrqGate>() };
}
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
macro_rules! waiters_lock {
    ($list:expr) => { $list.waiters.lock_irqsave::<hal_aarch64::ArmIrqGate>() };
}
#[cfg(not(target_os = "oxide-kernel"))]
macro_rules! waiters_lock {
    ($list:expr) => { $list.waiters.lock() };
}

/// FIFO wait list. Holds strong refs to parked tasks; drops them
/// on wake (after enqueueing on the runqueue).
pub struct WaitList {
    waiters: Spinlock<Vec<Arc<Task>>, WaitClass>,
}

impl WaitList {
    /// Publish the current task as an uninterruptible prepared waiter. The
    /// caller owns the resource-gate contract: it tests the condition, calls
    /// this while that gate still excludes the waker, drops the gate, then
    /// schedules and rechecks. Ordinary predicate waits use `wait_event`.
    /// # SAFETY: process context with a live runqueue; caller must schedule
    /// after dropping the resource gate and must finish/cancel on every exit.
    /// # C: O(1)
    pub unsafe fn prepare_to_wait(&self) {
        // SAFETY: this is the named prepared-wait form of `park` and forwards
        // the caller's publication/schedule contract unchanged.
        unsafe { self.park(); }
    }

    /// Timed uninterruptible [`prepare_to_wait`]. # SAFETY: see that method.
    ///
    /// This is for a caller that owns the completion rule itself (for example,
    /// a private deadline sleep) and therefore publishes before it schedules.
    pub unsafe fn prepare_to_wait_with_deadline(&self, deadline_ns: u64) {
        // SAFETY: forwards the prepared-wait contract with the absolute
        // deadline retained for the scheduler deadline scanner.
        unsafe { self.park_with_deadline(deadline_ns); }
    }

    /// Interruptible [`prepare_to_wait`]. # SAFETY: see that method.
    /// # C: O(1)
    pub unsafe fn prepare_to_wait_interruptible(&self) {
        // SAFETY: forwards the prepared-wait contract while adding the
        // signal-after-publication check required for an interruptible wait.
        unsafe { self.park_interruptible_with_deadline(0); }
    }

    /// Timed interruptible [`prepare_to_wait`]. # SAFETY: see that method.
    /// # C: O(1)
    pub unsafe fn prepare_to_wait_interruptible_with_deadline(&self, deadline_ns: u64) {
        // SAFETY: forwards the prepared-wait contract with the caller's
        // absolute deadline retained for the scheduler's deadline scanner.
        unsafe { self.park_interruptible_with_deadline(deadline_ns); }
    }

    /// Arm a deadline for the running task's existing prepared wait without
    /// re-publishing it. # SAFETY: the caller prepared this task on this list,
    /// still has not scheduled, and will drop its resource gate before doing so.
    /// # C: O(N armed)
    pub unsafe fn arm_current_prepared_deadline(&self, deadline_ns: u64) {
        if deadline_ns == 0 { return; }
        let Some(cur) = super::schedule::current() else { return };
        let Some(task) = crate::registry::lookup(cur.tid) else { return };
        // A wake that won before this timed commit made the task Runnable.
        // Never turn that wake back into Sleeping by re-publishing it.
        if task.state() != TaskState::Sleeping { return; }
        let slack = crate::hrtimeout::task_slack_ns(&task);
        crate::hrtimeout::arm(&task, deadline_ns, slack);
        if task.state() != TaskState::Sleeping {
            crate::hrtimeout::disarm(&task);
        }
    }

    /// # C: O(1)
    pub const fn new() -> Self {
        Self { waiters: Spinlock::new(Vec::new()) }
    }

    /// Park the running task on this list, marking it Sleeping.
    /// Caller MUST call `crate::schedule()` immediately
    /// after to yield. Caller MUST NOT hold any lock that a waker
    /// also needs to take (otherwise the waker deadlocks while
    /// we sleep).
    /// # SAFETY: caller is the running task on this CPU; preempt-
    /// off; runqueue installed via `install_global`. The `Arc`
    /// strong-count bump matches `Arc::from_raw` so the count
    /// stays balanced across park/wake.
    /// # C: O(1)
    /// # Lk: WaitList.waiters (TaskList class)
    pub unsafe fn park(&self) {
        // SAFETY: same contract as park_with_deadline; 0 deadline disables the timer-wake path.
        unsafe { self.park_with_deadline(0); }
    }

    /// F169: as `park` but also arms a wait expiry, so the timer IRQ rouses the
    /// task with `Eagain` semantics when the SO_*TIMEO window closes without
    /// another waker firing. Pass `0` for the deadline to disable the timer
    /// (== plain `park`).
    ///
    /// Grants the task's own `timer_slack_ns` — Linux's default for a generic
    /// timed wait (`hrtimer_nanosleep`, `futex_wait`, and
    /// `wait_event_hrtimeout` all pass exactly
    /// this). Callers that coalesce harder — poll/select/epoll, which spend
    /// 0.1% of the remaining timeout — use `park_with_deadline_range` with
    /// `hrtimeout::select_estimate_accuracy`.
    /// # SAFETY: see `park`. Caller still owns the post-park
    /// `schedule()` call.
    /// # C: O(N armed)
    pub unsafe fn park_with_deadline(&self, deadline_ns: u64) {
        let slack = super::schedule::current()
            .map(crate::hrtimeout::task_slack_ns).unwrap_or(0);
        // SAFETY: forwards the caller's contract unchanged; this wrapper only supplies the default slack.
        unsafe { self.park_with_deadline_range(deadline_ns, slack); }
    }

    /// [`park_with_deadline`] with an explicit coalescing window — Linux
    /// `schedule_hrtimeout_range(expires, delta, ...)`. The wait may end any
    /// time in `[deadline_ns, deadline_ns + slack_ns]`, never before.
    /// # SAFETY: see `park`.
    /// # C: O(N armed)
    pub unsafe fn park_with_deadline_range(&self, deadline_ns: u64, slack_ns: u64) {
        let rq = match super::runqueue::global() { Some(r) => r, None => return };
        let raw = rq.current.load(Ordering::Acquire);
        if raw.is_null() { return; }
        // SAFETY: rq.current is non-null after install_global; bump strong count to materialise an Arc the wait list can hold across schedule.
        unsafe { Arc::increment_strong_count(raw); }
        // SAFETY: matching Arc::from_raw consumes the bumped ref.
        let arc = unsafe { Arc::from_raw(raw) };
        // Keep one reference for the timeout arm after this function publishes
        // the other one to the wait list. The wait-list lock must not nest the
        // hrtimer lock: Hrtimeout ranks below TaskList.
        let timer_arc = Arc::clone(&arc);
        #[cfg(feature = "debug-desktop")]
        if deadline_ns != 0 && arc.with_exe_path(|p| p.map(|p| {
            p.contains("gnome-shell") || p.contains("mutter")
        }).unwrap_or(false))
            && MUTTER_DEADLINE_PARK_TRACE_REMAINING.fetch_update(
                Ordering::Relaxed, Ordering::Relaxed,
                |remaining| remaining.checked_sub(1)).is_ok()
        {
            klog::write_raw(b"[MUTTERWAIT park tid=");
            klog::write_dec_u64(arc.tid as u64);
            klog::write_raw(b" nr=");
            klog::write_dec_u64(arc.last_syscall_nr.load(Ordering::Relaxed) as u64);
            klog::write_raw(b" dl=");
            klog::write_dec_u64(deadline_ns);
            klog::write_raw(b"]\n");
        }
        let mut g = waiters_lock!(self);
        // Linux prepare_to_wait order: add the waiter, then publish Sleeping,
        // while holding the wait-queue lock. A waker can consequently observe
        // either the prior Runnable state or a visible Sleeping waiter; it can
        // never observe Sleeping while the queue is empty and lose the event.
        //
        // Dedup: drop any prior entry for this task before re-pushing.
        // A signal wake / deadline scanner rouses a parked task WITHOUT
        // popping it from the list; if the task then re-parks (its
        // pending signal was masked, condition still unmet) it would
        // leave two entries → wake_all double-enqueues → runqueue
        // corruption. retain drops the stale Arc, balancing its park
        // bump. See the Sleeping-guard in enqueue_runnable.
        let cur = raw as *const Task;
        g.retain(|a| Arc::as_ptr(a) != cur);
        g.push(arc);
        timer_arc.set_state(TaskState::Sleeping);
        drop(g);
        // Timer setup follows publication because its lock ranks below the
        // wait-list lock. A wake can win in this small interval, before an
        // expiry exists to cancel. Arm first, then retire it if that happened;
        // a wake after this check clears the same deadline in ttwu.
        crate::hrtimeout::arm(&timer_arc, deadline_ns, slack_ns);
        if timer_arc.state() != TaskState::Sleeping {
            crate::hrtimeout::disarm(&timer_arc);
        }
    }

    /// Park with a deadline while closing the signal-before-sleep race.
    /// # C: O(1)
    pub unsafe fn park_interruptible_with_deadline(&self, deadline_ns: u64) {
        // SAFETY: caller provides the same process-context contract required by
        // park_with_deadline; this wrapper only performs the post-publish check.
        unsafe { self.park_with_deadline(deadline_ns); }
        self.check_pending_after_park();
    }

    /// [`park_interruptible_with_deadline`] with an explicit coalescing window.
    /// # SAFETY: see `park`.
    /// # C: O(N armed)
    pub unsafe fn park_interruptible_with_deadline_range(&self, deadline_ns: u64, slack_ns: u64) {
        // SAFETY: same contract as `park_interruptible_with_deadline`; only the slack differs.
        unsafe { self.park_with_deadline_range(deadline_ns, slack_ns); }
        self.check_pending_after_park();
    }

    /// Close the signal-before-sleep race: a signal that arrived while this
    /// task was publishing itself Sleeping must not be missed.
    /// # C: O(1)
    fn check_pending_after_park(&self) {
        if super::sigpend::deliverable_signals_self() != 0 {
            if let Some(cur) = super::schedule::current() {
                if let Some(task) = crate::registry::lookup(cur.tid) {
                    super::sigpend::wake_if_sleeping(&task);
                }
            }
        }
    }

    /// Wake the longest-waiting task on this list (FIFO). No-op
    /// if empty. Sets state Runnable, lifts vruntime to the CFS
    /// minimum, enqueues on the runqueue, sets need_resched.
    /// # C: O(1)
    /// # Lk: WaitList.waiters then runqueue.inner
    pub fn wake_one(&self) {
        // Pop in FIFO order until a genuinely-Sleeping waiter is
        // enqueued. A stale entry (task already roused by a signal /
        // deadline scanner, or exiting) is dropped without consuming
        // the single wake — else a real sleeper could be skipped.
        loop {
            let popped: Option<Arc<Task>> = {
                let mut g = waiters_lock!(self);
                if g.is_empty() { None } else { Some(g.remove(0)) }
            };
            match popped {
                None => return,
                Some(t) => if Self::enqueue_runnable(t) { return; }
            }
        }
    }

    /// Wake every task on this list. Used by IPC commit paths
    /// where multiple waiters may now succeed (e.g. semop commit
    /// raises a value — different waiters needed different
    /// magnitudes).
    /// # C: O(N_waiters)
    /// # Lk: WaitList.waiters then runqueue.inner (per task)
    pub fn wake_all(&self) {
        let drained: Vec<Arc<Task>> = {
            let mut g = waiters_lock!(self);
            if g.is_empty() { return; }
            g.drain(..).collect()
        };
        for t in drained { let _ = Self::enqueue_runnable(t); }
    }

    /// True if any task is currently parked.
    /// # C: O(1)
    pub fn has_waiters(&self) -> bool {
        !waiters_lock!(self).is_empty()
    }

    /// Remove a stale registration for the currently running task.
    /// # C: O(N_waiters)
    pub fn remove_current(&self) {
        let Some(cur) = super::schedule::current() else { return };
        let ptr = cur as *const Task;
        waiters_lock!(self).retain(|task| Arc::as_ptr(task) != ptr);
        // A wake may win after wait-list publication but before the timeout is
        // armed. Retire that now-stale arm before this task can begin another
        // wait, just as finish_wait cancels a pending timeout on every exit.
        crate::hrtimeout::disarm(cur);
    }

    /// Cancel the current task's published park before it calls `schedule`.
    /// # C: O(N_waiters)
    pub fn cancel_current_park(&self) {
        let Some(cur) = super::schedule::current() else { return };
        let ptr = cur as *const Task;
        waiters_lock!(self).retain(|task| Arc::as_ptr(task) != ptr);
        crate::hrtimeout::disarm(cur);
        if cur.state() == TaskState::Sleeping { cur.set_state(TaskState::Runnable); }
    }

    /// Internal helper: transition a popped task to Runnable and
    /// enqueue on the global runqueue. Returns `true` if the task was
    /// actually enqueued, `false` if it was a stale entry (not
    /// Sleeping — already roused by a signal/deadline wake, or
    /// exiting/zombie) and was merely dropped. Dropping the `Arc`
    /// balances `park`'s strong-count bump. The Sleeping check is the
    /// systemic guard against enqueuing a dead task (corrupt context
    /// switch) or double-enqueuing an already-runnable one.
    fn enqueue_runnable(t: Arc<Task>) -> bool {
        // B2: route through try_to_wake_up so the wake picks the idlest
        // allowed CPU (select_task_rq) and IPIs it if remote — instead of
        // always waking local + waiting for the load balancer. ttwu does the
        // Sleeping→Runnable transition + sleeper credit + enqueue under the
        // TARGET rq's lock + resched_curr.
        // SAFETY: wake-site context; the Arc keeps `t` alive across the call.
        unsafe { super::try_to_wake_up(t) }
    }
}

impl Default for WaitList {
    fn default() -> Self { Self::new() }
}
