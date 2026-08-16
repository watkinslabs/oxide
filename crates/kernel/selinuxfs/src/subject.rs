// The SID a request to this filesystem is checked against.
//
// A write here is an operation on the security server by whoever wrote it, so
// the check needs the WRITER's label. Task labels are owned by the task
// subsystem, not by a filesystem, so the accessor is installed from there
// rather than stored here: a copy of a task's SID kept in this crate could
// disagree with the task's own field, and a check against a stale label is a
// check against the wrong subject.
//
// Until the owner installs one, the writer is the kernel itself, which is
// what the label of a request with no task behind it is.

use core::sync::atomic::{AtomicU32, Ordering};

use selinux::sidtab::Sid;
use sync::{SecurityPolicy as LockClass, Spinlock};

/// Accessor for the calling task's SID.
pub type SubjectFn = fn() -> Sid;

/// Installed accessor, if the task subsystem has installed one.
static SUBJECT: Spinlock<Option<SubjectFn>, LockClass> = Spinlock::new(None);

/// Number of writes checked against the fallback subject.
///
/// A non-zero count with no accessor installed says the interface is gating
/// on the kernel's own label rather than the caller's; the statistics nodes
/// are where that becomes visible instead of silent.
static FALLBACK_CHECKS: AtomicU32 = AtomicU32::new(0);

/// Install the accessor for the calling task's SID. # C: O(1)
pub fn set_subject_hook(f: SubjectFn) { *SUBJECT.lock() = Some(f); }

/// SID the current request is checked against. # C: O(1)
pub fn current_sid() -> Sid {
    let hook = *SUBJECT.lock();
    match hook {
        Some(f) => f(),
        None => {
            FALLBACK_CHECKS.fetch_add(1, Ordering::Relaxed);
            selinux_runtime::label::kernel_sid()
        }
    }
}

/// Writes so far checked against the fallback subject. # C: O(1)
pub fn fallback_checks() -> u32 { FALLBACK_CHECKS.load(Ordering::Relaxed) }
