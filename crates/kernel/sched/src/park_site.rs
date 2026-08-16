//! Where a blocked task is parked — the datum `/proc/<pid>/wchan` reports.
//!
//! The reference derives it by unwinding the blocked task's kernel stack and
//! taking the first return address that is not a scheduler function
//! (`__get_wchan`), then naming it through `kallsyms`. This kernel has no
//! symbol table to name an address with, so the wait site records ITSELF: every
//! blocking entry point is `#[track_caller]` and stores its caller's
//! `&'static Location` on the task. That yields the same fact — the source
//! position of the sleep the task is sitting in — as a `file:line` a log reader
//! can act on without a symbol lookup.
//!
//! The publication rule is the reference's: the value only means anything for a
//! task that is off-CPU and blocked, so [`reportable`] refuses it otherwise
//! rather than handing back a stale site for a task that is running.

use core::panic::Location;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::TaskState;

/// Last blocking site recorded on a task. Holds a `&'static Location`, which
/// the compiler materialises in rodata, so the pointer stays valid for the
/// kernel's lifetime and can be read from hard-IRQ context (the task dump).
pub struct ParkSite(AtomicUsize);

impl ParkSite {
    /// # C: O(1)
    pub const fn new() -> Self { Self(AtomicUsize::new(0)) }

    /// Record the site the running task is about to block at. # C: O(1)
    pub fn set(&self, loc: &'static Location<'static>) {
        self.0.store(loc as *const Location<'static> as usize, Ordering::Relaxed);
    }

    /// Forget the recorded site. # C: O(1)
    pub fn clear(&self) { self.0.store(0, Ordering::Relaxed); }

    /// The recorded site, or `None` if nothing has been recorded. # C: O(1)
    pub fn get(&self) -> Option<&'static Location<'static>> {
        let raw = self.0.load(Ordering::Relaxed);
        if raw == 0 { return None; }
        // SAFETY: `set` is the only writer and stores a `&'static Location`
        // produced by `#[track_caller]`, which lives in rodata for the whole
        // kernel lifetime; the pointer is therefore always dereferenceable.
        Some(unsafe { &*(raw as *const Location<'static>) })
    }
}

impl Default for ParkSite {
    fn default() -> Self { Self::new() }
}

/// The reference's `get_wchan` gate: a site is only reported for a task that is
/// neither running nor mid-wake and is off every runqueue. Reporting one for a
/// running task would name the last sleep it woke from, not where it is.
/// # C: O(1)
pub const fn reportable(state: TaskState, on_rq: bool, on_cpu: bool) -> bool {
    if on_rq || on_cpu { return false; }
    match state {
        TaskState::Sleeping | TaskState::Stopped => true,
        TaskState::Runnable | TaskState::Waking | TaskState::Zombie => false,
    }
}

/// Record `loc` as the running task's blocking site. No-op before the runqueue
/// exists (early boot) — there is no task to attribute it to. # C: O(1)
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn note(loc: &'static Location<'static>) {
    #[cfg(test)]
    LAST_NOTE.set(loc);
    if let Some(task) = crate::live::schedule::current() { task.park_site.set(loc); }
}

/// Hosted test seam. A host build installs no runqueue, so [`note`] has no
/// current task to attribute a site to; recording it here as well lets a test
/// prove that a blocking entry point forwards its CALLER's position rather than
/// its own — the one property the whole mechanism rests on.
#[cfg(test)]
pub(crate) static LAST_NOTE: ParkSite = ParkSite::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[track_caller]
    fn caller_site() -> &'static Location<'static> { Location::caller() }

    #[test]
    fn a_recorded_site_reads_back_and_clears() {
        let site = ParkSite::new();
        assert!(site.get().is_none(), "a fresh site must report nothing");
        let here = caller_site();
        site.set(here);
        let read = site.get().expect("recorded site must read back");
        assert_eq!(read.file(), here.file());
        assert_eq!(read.line(), here.line());
        site.clear();
        assert!(site.get().is_none(), "clear must retract the site");
    }

    #[test]
    fn track_caller_names_the_wait_site_not_the_helper() {
        // The whole mechanism rests on the caller's line being recorded, not
        // the line inside the helper that records it.
        let here = line!() + 1;
        let site = caller_site();
        assert_eq!(site.line(), here);
        assert!(site.file().ends_with("park_site.rs"));
    }

    #[test]
    fn only_a_blocked_off_cpu_task_reports_a_site() {
        assert!(reportable(TaskState::Sleeping, false, false));
        assert!(reportable(TaskState::Stopped, false, false));
        // Running, or queued to run: the recorded site is stale by definition.
        assert!(!reportable(TaskState::Runnable, false, false));
        assert!(!reportable(TaskState::Waking, false, false));
        assert!(!reportable(TaskState::Zombie, false, false));
        assert!(!reportable(TaskState::Sleeping, true, false), "on a runqueue");
        assert!(!reportable(TaskState::Sleeping, false, true), "on a CPU");
    }
}
