// Init-step tracing (`initcall_debug`).
//
// Each boot init step announces itself BEFORE it runs and reports its result
// and elapsed time after. That ordering is the whole point: a step that never
// returns has already printed its own name, so a boot that hangs names the
// step it stopped in instead of stopping silently.
//
// Lives with the record ring rather than with the boot sequence because it is
// a printk-shaped tracer and because the boot sequence is target-gated — a
// decision placed there could not be tested at all.

use core::sync::atomic::{AtomicBool, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);

/// Is init-step tracing on? # C: O(1)
pub fn enabled() -> bool { ENABLED.load(Ordering::Acquire) }

/// Record the boot line's `initcall_debug` request. # C: O(1)
pub fn set_enabled(on: bool) { ENABLED.store(on, Ordering::Release); }

/// Announce entry to init step `name` and return its start timestamp. The
/// line is emitted before the step runs, so a step that hangs is named.
/// # C: O(name.len())
pub fn start(name: &str) -> u64 {
    if !enabled() { return 0; }
    let now = crate::monotonic_ns().unwrap_or(0);
    crate::write_raw_at(b"calling  ", crate::syslog::LOGLEVEL_DEBUG);
    crate::write_raw_at(name.as_bytes(), crate::syslog::LOGLEVEL_DEBUG);
    crate::write_raw_at(b"\n", crate::syslog::LOGLEVEL_DEBUG);
    now
}

/// Report init step `name` finishing with `ret`, `started` nanoseconds ago.
/// The elapsed time is what separates a slow step from a hung one.
/// # C: O(name.len())
pub fn finish(name: &str, started: u64, ret: i32) {
    if !enabled() { return; }
    let usecs = elapsed_usecs(started, crate::monotonic_ns().unwrap_or(started));
    crate::write_raw_at(b"initcall ", crate::syslog::LOGLEVEL_DEBUG);
    crate::write_raw_at(name.as_bytes(), crate::syslog::LOGLEVEL_DEBUG);
    crate::write_raw_at(b" returned ", crate::syslog::LOGLEVEL_DEBUG);
    if ret < 0 {
        crate::write_raw_at(b"-", crate::syslog::LOGLEVEL_DEBUG);
        crate::write_dec_at(ret.unsigned_abs() as u64, crate::syslog::LOGLEVEL_DEBUG);
    } else {
        crate::write_dec_at(ret as u64, crate::syslog::LOGLEVEL_DEBUG);
    }
    crate::write_raw_at(b" after ", crate::syslog::LOGLEVEL_DEBUG);
    crate::write_dec_at(usecs, crate::syslog::LOGLEVEL_DEBUG);
    crate::write_raw_at(b" usecs\n", crate::syslog::LOGLEVEL_DEBUG);
}

/// Announce entry to an init LEVEL — a group of steps that run together.
/// # C: O(name.len())
pub fn level(name: &str) {
    if !enabled() { return; }
    crate::write_raw_at(b"entering initcall level: ", crate::syslog::LOGLEVEL_DEBUG);
    crate::write_raw_at(name.as_bytes(), crate::syslog::LOGLEVEL_DEBUG);
    crate::write_raw_at(b"\n", crate::syslog::LOGLEVEL_DEBUG);
}

/// Microseconds between two monotonic readings, saturating rather than
/// wrapping so a clock that has not started yet reports 0 instead of an
/// astronomically large duration.
/// # C: O(1)
pub fn elapsed_usecs(started: u64, now: u64) -> u64 { now.saturating_sub(started) / 1_000 }

/// Run one init step under the tracer. Tracing off makes this exactly the
/// call it wraps — the boot sequence keeps one spelling whether or not the
/// parameter was passed, so there is no second, untraced path to drift.
/// Always inlined: a wrapper frame between a caller and a deep init step both
/// adds to that step's stack depth and renames the path the depth gate tracks,
/// and the boot path already runs close to its ceiling.
/// # C: cost of `f`
#[inline(always)]
pub fn run<T, F: FnOnce() -> T>(name: &str, f: F) -> T {
    let t = start(name);
    let out = f();
    finish(name, t, 0);
    out
}

/// Run an init step whose result is a `Result`, reporting the outcome as the
/// return value the way a failing step must be reported.
/// Always inlined, for the reason given on [`run`].
/// # C: cost of `f`
#[inline(always)]
pub fn run_result<T, E, F: FnOnce() -> Result<T, E>>(name: &str, f: F) -> Result<T, E> {
    let t = start(name);
    let out = f();
    finish(name, t, if out.is_ok() { 0 } else { -1 });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::string::String;
    use std::sync::Mutex;

    static SEEN: Mutex<String> = Mutex::new(String::new());
    fn capture(b: &[u8]) {
        SEEN.lock().unwrap_or_else(|e| e.into_inner()).push_str(&String::from_utf8_lossy(b));
    }

    #[test]
    fn elapsed_is_microseconds() {
        assert_eq!(elapsed_usecs(1_000_000_000, 1_000_500_000), 500);
        assert_eq!(elapsed_usecs(0, 1_000), 1);
        assert_eq!(elapsed_usecs(0, 999), 0);
    }

    #[test]
    fn a_clock_that_went_backwards_reports_zero_not_a_wrap() {
        assert_eq!(elapsed_usecs(5_000_000_000, 1), 0);
    }

    #[test]
    fn tracing_is_off_until_the_boot_line_asks() {
        set_enabled(false);
        assert!(!enabled());
        assert_eq!(start("noisy"), 0, "a disabled tracer takes no timestamp");
    }

    /// The load-bearing property: the entry line is on the wire BEFORE the
    /// step runs. A step that never returns has then already named itself, so
    /// the last line of a hung boot's log IS the step it stopped in. Emitting
    /// the name after the call would make a hang anonymous again.
    #[test]
    fn the_entry_line_is_emitted_before_the_step_runs() {
        let _g = crate::console::test_lock();
        SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
        crate::set_byte_sink(capture);
        set_enabled(true);
        run("stuck_step", || {
            // Stand-in for a step that never returns: what has reached the
            // console at THIS instant is all a hung boot would ever show.
            let at_hang = SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone();
            assert!(at_hang.contains("calling  stuck_step"), "a hang here would be anonymous: {at_hang:?}");
            assert!(!at_hang.contains("returned"), "the step has not returned yet");
        });
        let after = SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(after.contains("stuck_step returned 0 after"), "a completed step reports its duration: {after:?}");
        set_enabled(false);
        crate::clear_byte_sink();
    }

    #[test]
    fn run_returns_the_step_value_with_tracing_either_way() {
        set_enabled(false);
        assert_eq!(run("step", || 7), 7);
        set_enabled(true);
        assert_eq!(run("step", || 7), 7, "tracing must not change what a step returns");
        assert_eq!(run_result::<u8, u8, _>("step", || Err(3)).unwrap_err(), 3);
        set_enabled(false);
    }
}
