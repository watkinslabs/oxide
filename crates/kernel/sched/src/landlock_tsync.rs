// Landlock cross-thread enforcement — Linux `security/landlock/tsync.c`.
//
// A TSYNC caller must not write sibling credentials in a registry walk.  That
// exposes a window in which siblings execute under different policies, misses
// clones published during the walk, and lets two concurrent walks interleave.
// Linux instead queues pseudo-signal task_work on every sibling.  Each target
// prepares on its own kernel stack, waits at a barrier, then commits only after
// every sibling (including clones discovered by repeated scans) is parked.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

use landlock::Domain;

use crate::Task;
#[cfg(any(target_os = "oxide-kernel", feature = "hosted"))]
use crate::TaskState;

const PREPARING: u8 = 0;
const COMMIT: u8 = 1;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Shared two-barrier state owned by one TSYNC syscall and its sibling work.
pub struct Transaction {
    id: u64,
    phase: AtomicU8,
    expected: AtomicU32,
    prepared: AtomicU32,
    finished: AtomicU32,
    domain: Option<Arc<Domain>>,
    set_no_new_privs: bool,
}

impl Transaction {
    fn new(domain: Option<Arc<Domain>>, set_no_new_privs: bool) -> Self {
        let mut id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        if id == 0 {
            id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        }
        Self {
            id,
            phase: AtomicU8::new(PREPARING),
            expected: AtomicU32::new(0),
            prepared: AtomicU32::new(0),
            finished: AtomicU32::new(0),
            domain,
            set_no_new_privs,
        }
    }

    fn all_prepared(&self) -> bool {
        self.prepared.load(Ordering::Acquire) == self.expected.load(Ordering::Acquire)
    }

    fn all_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire) == self.expected.load(Ordering::Acquire)
    }
}

/// Result of attempting to start a group transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartError {
    /// Another thread owns the process TSYNC writer exclusion.  Linux returns
    /// `restart_syscall()` so this thread runs the queued task work first.
    Restart,
}

/// Repeat discovery until a scan finds no task that has not already entered
/// the barrier. A child created during an earlier scan appears in the next
/// one; the wait between scans ensures its creator is parked before the final
/// empty scan can end discovery.
fn discover_until_stable(mut discover: impl FnMut() -> bool, mut wait: impl FnMut()) {
    loop {
        let found = discover();
        wait();
        if !found { break; }
    }
}

/// Whether `task` has pseudo-signal work that must run before user mode.
/// # C: O(1)
pub fn pending(task: &Task) -> bool { task.notify_signal.load(Ordering::Acquire) }

/// Queue one target exactly once for this transaction.
#[cfg(any(target_os = "oxide-kernel", feature = "hosted"))]
fn enqueue(txn: &Arc<Transaction>, task: &Arc<Task>) -> bool {
    if task.exiting.load(Ordering::Acquire) || task.state() == TaskState::Zombie {
        return false;
    }
    if task.landlock_tsync_id.load(Ordering::Acquire) == txn.id { return false; }

    let mut slot = task.landlock_tsync_work.lock();
    if task.landlock_tsync_id.load(Ordering::Acquire) == txn.id { return false; }
    // The thread-group writer exclusion permits only this group's one TSYNC
    // work. A non-empty different slot can only be a transaction the target
    // must run before this contender retries.
    if slot.is_some() { return false; }
    txn.expected.fetch_add(1, Ordering::AcqRel);
    task.landlock_tsync_id.store(txn.id, Ordering::Release);
    *slot = Some(Arc::clone(txn));
    task.notify_signal.store(true, Ordering::Release);
    drop(slot);

    // Linux `set_notify_signal`: wake TASK_INTERRUPTIBLE, otherwise kick the
    // CPU so a user-running task enters the common return path promptly.
    crate::live::signal_wake_up(task);
    true
}

/// Run a Linux-shaped TSYNC transaction from `landlock_restrict_self`.
///
/// Every existing sibling enters its own return-to-user work and parks at the
/// preparation barrier.  The repeated scan captures a child published by a
/// sibling just before that sibling reaches the work; once all discovered
/// siblings are parked, none can still clone, so the final empty scan closes
/// the race.  Only then does the commit phase begin.
/// # C: O(rounds * N_tasks)
/// # Sleeps: yes
#[cfg(target_os = "oxide-kernel")]
pub fn restrict_siblings(cur: &Task, domain: Option<Arc<Domain>>,
                         set_no_new_privs: bool) -> Result<(), StartError> {
    let _exec_update = cur.thread_group.try_exec_update().ok_or(StartError::Restart)?;
    let txn = Arc::new(Transaction::new(domain, set_no_new_privs));

    discover_until_stable(
        || {
            let mut found = false;
            let tgid = cur.tgid.load(Ordering::Acquire);
            for task in crate::registry::thread_group(tgid) {
                if task.tid != cur.tid { found |= enqueue(&txn, &task); }
            }
            found
        },
        || {
            while !txn.all_prepared() {
                // Process context, no lock held. Class-specific yield ensures
                // a UP caller cannot starve the siblings whose ACKs it awaits.
                // SAFETY: syscall process context on the current task's stack;
                // no tracked lock is held across the scheduler handoff.
                unsafe { crate::live::sched_yield(); }
            }
        },
    );

    txn.phase.store(COMMIT, Ordering::Release);
    while !txn.all_finished() {
        // SAFETY: syscall process context on the current task's stack; the
        // transaction guard is atomic state, not a lock held across schedule.
        unsafe { crate::live::sched_yield(); }
    }

    if let Some(domain) = txn.domain.as_ref() {
        *cur.landlock_domain.lock() = Some(Arc::clone(domain));
    }
    if txn.set_no_new_privs { cur.no_new_privs.store(true, Ordering::Release); }
    Ok(())
}

/// Consume the current thread's pseudo-signal work.  The credential change is
/// made by the owning thread, never by the initiator's CPU.
/// # C: O(wait for group barrier)
/// # Sleeps: yes
#[cfg(target_os = "oxide-kernel")]
pub fn run_current_work() {
    let Some(cur) = crate::live::current() else { return };
    let txn = cur.landlock_tsync_work.lock().take();
    cur.notify_signal.store(false, Ordering::Release);
    let Some(txn) = txn else { return };

    txn.prepared.fetch_add(1, Ordering::AcqRel);
    while txn.phase.load(Ordering::Acquire) == PREPARING {
        // SAFETY: common return-to-user process context on this task's own
        // stack, with the work-slot lock dropped before the scheduler handoff.
        unsafe { crate::live::sched_yield(); }
    }
    if let Some(domain) = txn.domain.as_ref() {
        *cur.landlock_domain.lock() = Some(Arc::clone(domain));
    }
    if txn.set_no_new_privs { cur.no_new_privs.store(true, Ordering::Release); }
    txn.finished.fetch_add(1, Ordering::AcqRel);
}

/// Remove work that can no longer run because this task entered `do_exit`.
/// Mirrors Linux `task_work_add(...)= -ESRCH` / cancellation accounting.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn cancel_current_on_exit(task: &Task) {
    let txn = task.landlock_tsync_work.lock().take();
    task.notify_signal.store(false, Ordering::Release);
    if let Some(txn) = txn {
        txn.prepared.fetch_add(1, Ordering::AcqRel);
        txn.finished.fetch_add(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SchedClass;

    #[test]
    fn both_barriers_cover_every_enrolled_target() {
        let txn = Transaction::new(None, true);
        txn.expected.store(3, Ordering::Release);
        assert!(!txn.all_prepared());
        txn.prepared.store(3, Ordering::Release);
        assert!(txn.all_prepared());
        assert!(!txn.all_finished());
        txn.finished.store(3, Ordering::Release);
        assert!(txn.all_finished());
    }

    #[test]
    fn generations_are_nonzero_and_unique() {
        let a = Transaction::new(None, false);
        let b = Transaction::new(None, false);
        assert_ne!(a.id, 0);
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn exec_and_tsync_share_one_writer_exclusion() {
        let task = Task::new(0x7450, "exec-tsync", SchedClass::Normal { weight: 1024 });
        let first = task.thread_group.try_exec_update().expect("first writer");
        assert!(task.thread_group.try_exec_update().is_none(), "second writer must restart");
        drop(first);
        assert!(task.thread_group.try_exec_update().is_some(), "guard drop must release writer");
    }

    #[test]
    fn a_clone_published_during_the_first_round_is_discovered_in_the_second() {
        // Round one queues an existing sibling. While that sibling is still
        // returning from clone(2), it publishes a child. The wait parks both;
        // round two must discover the child, and only round three is empty.
        let rounds = [true, true, false];
        let mut next = 0usize;
        let mut waits = 0usize;
        discover_until_stable(
            || { let found = rounds[next]; next += 1; found },
            || { waits += 1; },
        );
        assert_eq!(next, 3, "discovery must continue through the first empty scan");
        assert_eq!(waits, 3, "every scan must close its preparation barrier");
    }
}
