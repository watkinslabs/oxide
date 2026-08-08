// WARN_ON: report a broken invariant and keep going — or, under
// `panic_on_warn`, stop the machine at the first one.
//
// A warning is not an error return. It marks a condition the code believes
// cannot happen, at the point it happened, so the state that produced it is
// still on the stack and in the log. Without this concept `panic_on_warn` has
// nothing to act on, and a broken invariant is a line in a log nobody reads.
//
// Distinct from `kwarn!`, deliberately: `kwarn!` is a log LEVEL and must stay
// one. Turning every warning-level line into a panic would make
// `panic_on_warn` mean "panic on anything mildly notable", which is not what
// it is for and would make the parameter unusable.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::oops;

/// Count of warnings reported since boot. A warning that fired once and was
/// scrolled off the console is still visible here.
static WARN_COUNT: AtomicU64 = AtomicU64::new(0);

/// How many warnings have been reported. # C: O(1)
pub fn warn_count() -> u64 { WARN_COUNT.load(Ordering::Acquire) }

/// Report a broken invariant at `origin`, then panic if the boot line asked
/// for that. `origin` names the site; it is a compile-time literal so the
/// warning path allocates and formats nothing.
/// # C: O(origin.len())
pub fn warn(origin: &'static str) {
    WARN_COUNT.fetch_add(1, Ordering::AcqRel);
    crate::write_primary_raw(b"------------[ cut here ]------------\n");
    crate::write_primary_raw(b"WARNING: ");
    crate::write_primary_raw(origin.as_bytes());
    crate::write_primary_raw(b"\n---[ end trace ]---\n");
    check_panic_on_warn(origin);
}

/// Report `origin` when `cond` holds, and return `cond`, so a caller can both
/// warn and branch on the same expression the way the condition is written.
/// # C: O(1) when `cond` is false
#[inline]
pub fn warn_on(cond: bool, origin: &'static str) -> bool {
    if cond { warn(origin); }
    cond
}

/// Report `origin` the FIRST time `cond` holds at this site and never again.
/// `seen` is the site's own latch, so a warning inside a hot loop costs one
/// line rather than a flood that pushes the cause off the console.
/// # C: O(1)
#[inline]
pub fn warn_on_once(cond: bool, seen: &AtomicBool, origin: &'static str) -> bool {
    if cond && !seen.swap(true, Ordering::AcqRel) { warn(origin); }
    cond
}

/// Panic if `panic_on_warn` was requested. Separate from [`warn`] so a caller
/// that reports a broken invariant its own way still honours the parameter —
/// a second reporting path that skipped this check would make the parameter
/// depend on which site happened to fire.
/// # C: O(1)
pub fn check_panic_on_warn(origin: &'static str) {
    if !oops::panic_on_warn() { return; }
    crate::write_primary_raw(b"[PANIC] panic_on_warn set: ");
    crate::write_primary_raw(origin.as_bytes());
    crate::write_primary_raw(b"\n");
    panic!("panic_on_warn set");
}

/// Report a broken invariant, naming the site. `WARN!("what happened")`.
/// Message must be a literal per `07§5` — the warning path formats nothing.
#[macro_export]
macro_rules! kwarn_on {
    ($cond:expr, $msg:literal $(,)?) => { $crate::warn::warn_on($cond, concat!($msg, " at ", file!(), ":", line!())) };
}

/// Unconditional form of [`kwarn_on!`], for a branch that is already known to
/// be the impossible one.
#[macro_export]
macro_rules! kwarn_here {
    ($msg:literal $(,)?) => { $crate::warn::warn(concat!($msg, " at ", file!(), ":", line!())) };
}

/// Once-per-site form of [`kwarn_on!`].
#[macro_export]
macro_rules! kwarn_on_once {
    ($cond:expr, $msg:literal $(,)?) => {{
        static __WARNED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        $crate::warn::warn_on_once($cond, &__WARNED, concat!($msg, " at ", file!(), ":", line!()))
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::string::String;
    use std::sync::Mutex;

    static SEEN: Mutex<String> = Mutex::new(String::new());
    fn capture(b: &[u8]) { SEEN.lock().unwrap_or_else(|e| e.into_inner()).push_str(&String::from_utf8_lossy(b)); }

    fn start() -> std::sync::MutexGuard<'static, ()> {
        let g = crate::console::test_lock();
        SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
        crate::set_byte_sink(capture);
        g
    }
    fn seen() -> String { SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone() }

    #[test]
    fn a_false_condition_reports_nothing() {
        let _g = start();
        let before = warn_count();
        assert!(!warn_on(false, "must not fire"));
        assert_eq!(seen(), "", "a healthy path emits zero bytes");
        assert_eq!(warn_count(), before);
        crate::clear_byte_sink();
    }

    #[test]
    fn a_true_condition_reports_and_returns_the_condition() {
        let _g = start();
        let before = warn_count();
        assert!(warn_on(true, "invariant broken here"), "the condition is returned so the caller can branch on it");
        let out = seen();
        assert!(out.contains("cut here"), "{out}");
        assert!(out.contains("WARNING: invariant broken here"), "{out}");
        assert_eq!(warn_count(), before + 1);
        crate::clear_byte_sink();
    }

    #[test]
    fn once_fires_once_however_often_the_condition_holds() {
        let _g = start();
        let latch = AtomicBool::new(false);
        for _ in 0..50 { assert!(warn_on_once(true, &latch, "hot loop invariant")); }
        assert_eq!(seen().matches("WARNING:").count(), 1, "a warning in a loop must not push the cause off the console");
        crate::clear_byte_sink();
    }

    #[test]
    fn a_warning_does_not_panic_unless_the_boot_line_asked() {
        let _g = start();
        oops::set_panic_on_warn(false);
        warn("this must return");
        assert!(seen().contains("WARNING:"));
        crate::clear_byte_sink();
    }

    /// The parameter's whole point: the first broken invariant stops the
    /// machine, so the state that produced it is what gets reported rather
    /// than whatever it corrupts later.
    #[test]
    fn panic_on_warn_turns_the_first_warning_into_a_panic() {
        let _g = start();
        oops::set_panic_on_warn(true);
        let hit = std::panic::catch_unwind(|| warn("invariant broken"));
        oops::set_panic_on_warn(false);
        assert!(hit.is_err(), "panic_on_warn must stop at the warning, not carry on past it");
        crate::clear_byte_sink();
    }

    #[test]
    fn the_check_is_reusable_by_a_site_that_reports_its_own_way() {
        let _g = start();
        oops::set_panic_on_warn(true);
        let hit = std::panic::catch_unwind(|| check_panic_on_warn("reported elsewhere"));
        oops::set_panic_on_warn(false);
        assert!(hit.is_err(), "a second reporting path must honour the same parameter");
        crate::clear_byte_sink();
    }
}
