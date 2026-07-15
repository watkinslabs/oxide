use core::sync::atomic::{AtomicBool, Ordering};

use super::gc;

static PASS_PAUSED: AtomicBool = AtomicBool::new(false);
static RELEASE_PASS: AtomicBool = AtomicBool::new(false);

std::thread_local! {
    static PAUSE_THIS_COLLECTOR: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// Pause the armed collector after one owned pass. # C: O(wait)
pub(super) fn pause_after_pass() {
    if !PAUSE_THIS_COLLECTOR.with(|armed| armed.replace(false)) { return; }
    PASS_PAUSED.store(true, Ordering::Release);
    while !RELEASE_PASS.load(Ordering::Acquire) { std::thread::yield_now(); }
    PASS_PAUSED.store(false, Ordering::Release);
}

/// Prepare the deterministic post-pass collector handoff. # C: O(1)
pub(crate) fn prepare_pause_after_pass() {
    RELEASE_PASS.store(false, Ordering::Release);
    PASS_PAUSED.store(false, Ordering::Release);
}

/// Reserve collector ownership for a deterministic test owner. # C: O(wait)
pub(crate) fn reserve_collection() -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if gc::test_try_reserve_collection() { return true; }
        if std::time::Instant::now() >= deadline { return false; }
        std::thread::yield_now();
    }
}

/// Run a reserved collector owner and pause after its first pass. # C: O(collection)
pub(crate) fn collect_reserved_with_pause_after_pass() {
    PAUSE_THIS_COLLECTOR.with(|armed| armed.set(true));
    gc::test_collect_reserved();
}

/// Complete reserved ownership synchronously when its worker cannot start. # C: O(collection)
pub(crate) fn cancel_reserved_collection() {
    gc::test_collect_reserved();
}

/// Wait for the collector to reach the armed handoff. # C: O(wait)
pub(crate) fn wait_pass_paused() -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !PASS_PAUSED.load(Ordering::Acquire) {
        if std::time::Instant::now() >= deadline { return false; }
        std::thread::yield_now();
    }
    true
}

/// Release a collector paused at the test handoff. # C: O(1)
pub(crate) fn release_paused_pass() {
    RELEASE_PASS.store(true, Ordering::Release);
}
