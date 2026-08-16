// The subject side of a check, read from whoever owns tasks.
//
// This crate deliberately sits below the task: it stores no per-task label and
// never could, because the task owner already has one and a second copy would
// answer a check with a label the task no longer carries. The owner installs a
// reader instead, and a build with no reader answers with the kernel's own
// label — the same answer a check made from a kernel thread gives.

use sync::{Spinlock, TaskList as TaskListClass};

use selinux::sidtab::Sid;

use crate::label::kernel_sid;

/// Reader for the current thread's own label.
static CURRENT_SID: Spinlock<Option<fn() -> Sid>, TaskListClass> = Spinlock::new(None);

/// Reader for the label the current thread staged for its next new object.
static FSCREATE_SID: Spinlock<Option<fn() -> Option<Sid>>, TaskListClass> = Spinlock::new(None);

/// Install the current-label reader. Idempotent. # C: O(1)
pub fn set_current_sid_source(f: fn() -> Sid) { *CURRENT_SID.lock() = Some(f); }

/// Install the staged-object-label reader. Idempotent. # C: O(1)
pub fn set_fscreate_sid_source(f: fn() -> Option<Sid>) { *FSCREATE_SID.lock() = Some(f); }

/// Label of the thread asking the question. # C: O(1)
pub fn current_sid() -> Sid {
    // The reader is copied out and the guard dropped before it runs: it reads
    // task state under the task owner's own lock, and holding this one across
    // that would order two locks that have no order between them.
    let reader = *CURRENT_SID.lock();
    match reader { Some(f) => f(), None => kernel_sid() }
}

/// Label the thread staged for the next object it creates, if any. # C: O(1)
///
/// Absent by default: a thread that has staged nothing must take the label the
/// policy computes, never a stale one from an earlier creation.
pub fn fscreate_sid() -> Option<Sid> {
    let reader = *FSCREATE_SID.lock();
    match reader { Some(f) => f(), None => None }
}
