// Serialisation for every test that touches the process-global image slots.
//
// `store` owns two static slots behind a try-lock, and `cargo test` runs the
// crate's tests on parallel threads — so without this gate one test holds the
// kexec lock while another calls into the store and gets `Busy` from a
// concurrency the test never asked for. That is precisely the EBUSY the
// subsystem is supposed to report, which is why the flake looked like a real
// answer: passes alone, fails in the suite.
//
// The gate does NOT weaken the EBUSY contract. A caller that finds the lock
// held must still be refused, and `tests::file` still asserts that — by
// nesting `with_kexec_lock` explicitly, which is deterministic and does not
// depend on which thread the harness happens to schedule.
//
// Same shape as the rest of the tree (`sched`'s zombie-reclaim and timer-list
// suites): a private `static LOCK` behind a helper, taken as the first line of
// every case that reaches global state, paired with a reset so a case never
// inherits its predecessor's slots.

use crate::frames::Frames;

/// Take the serialisation gate. Poison is ignored: a panicking test has
/// already failed, and refusing the lock afterwards would convert one failure
/// into a cascade of unrelated ones.
pub fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Take the gate AND reset every global the store owns, so a case starts from
/// the state a fresh boot has. Returns the guard, which must be held for the
/// whole case — dropping it early re-opens the race.
#[must_use]
pub fn exclusive_store<F: Frames>(f: &mut F) -> std::sync::MutexGuard<'static, ()> {
    let g = test_lock();
    crate::store::clear_for_tests(f);
    g
}
