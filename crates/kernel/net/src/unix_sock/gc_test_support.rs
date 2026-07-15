use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::gc;

static PASS_PAUSED: AtomicBool = AtomicBool::new(false);
static RELEASE_PASS: AtomicBool = AtomicBool::new(false);
static PENDING_MARKED: AtomicBool = AtomicBool::new(false);
static NEXT_RUNNING_OBSERVER: AtomicU64 = AtomicU64::new(1);
static RUNNING_OBSERVED: AtomicU64 = AtomicU64::new(0);
static RELEASED_RUNNING_OBSERVER: AtomicU64 = AtomicU64::new(0);
static IDLE_ACQUIRE_MARKED: AtomicU64 = AtomicU64::new(0);

std::thread_local! {
    static PAUSE_THIS_COLLECTOR: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    static PANIC_AFTER_PAUSE: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    static MARK_PENDING_REQUEST: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    static PAUSE_ON_RUNNING: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
    static MARK_IDLE_ACQUIRE: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// Pause the armed collector after one owned pass. # C: O(wait)
pub(super) fn pause_after_pass() {
    if !PAUSE_THIS_COLLECTOR.with(|armed| armed.replace(false)) { return; }
    PASS_PAUSED.store(true, Ordering::Release);
    while !RELEASE_PASS.load(Ordering::Acquire) { std::thread::yield_now(); }
    PASS_PAUSED.store(false, Ordering::Release);
    if PANIC_AFTER_PAUSE.with(|armed| armed.replace(false)) {
        panic!("injected collector owner unwind");
    }
}

/// Pause an armed requester after it observes a running owner. # C: O(wait)
pub(super) fn pause_after_observing_running(state: u8) {
    let generation = PAUSE_ON_RUNNING.with(|armed| armed.replace(0));
    if state != 1 || generation == 0 { return; }
    RUNNING_OBSERVED.fetch_max(generation, Ordering::Release);
    while RELEASED_RUNNING_OBSERVER.load(Ordering::Acquire) < generation {
        std::thread::yield_now();
    }
}

/// Record that the armed requester published the pending transition. # C: O(1)
pub(super) fn note_pending_request() {
    if MARK_PENDING_REQUEST.with(|armed| armed.replace(false)) {
        PENDING_MARKED.store(true, Ordering::Release);
    }
}

/// Record that the armed requester acquired idle collector ownership. # C: O(1)
pub(super) fn note_idle_acquire() {
    let generation = MARK_IDLE_ACQUIRE.with(|armed| armed.replace(0));
    if generation != 0 {
        IDLE_ACQUIRE_MARKED.fetch_max(generation, Ordering::Release);
    }
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

fn run_reserved(panic_after_pause: bool) {
    PAUSE_THIS_COLLECTOR.with(|armed| armed.set(true));
    PANIC_AFTER_PAUSE.with(|armed| armed.set(panic_after_pause));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(gc::test_collect_reserved));
    if let Err(payload) = result {
        gc::test_recover_collection_after_unwind();
        std::panic::resume_unwind(payload);
    }
}

/// Run a reserved collector owner and pause after its first pass. # C: O(collection)
pub(crate) fn collect_reserved_with_pause_after_pass() {
    run_reserved(false);
}

/// Run a reserved owner that unwinds at the deterministic handoff. # C: O(collection)
pub(crate) fn unwind_reserved_after_pause() {
    run_reserved(true);
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

/// Arm this thread to identify its successful pending publication. # C: O(1)
pub(crate) fn mark_pending_request() {
    PENDING_MARKED.store(false, Ordering::Release);
    MARK_PENDING_REQUEST.with(|armed| armed.set(true));
}

/// True when the specifically armed requester published pending. # C: O(1)
pub(crate) fn pending_request_was_marked() -> bool {
    PENDING_MARKED.load(Ordering::Acquire)
}

/// RAII release for a requester paused after observing a running owner.
pub(crate) struct RunningObserverRelease { generation: u64, released: bool }

impl RunningObserverRelease {
    /// Prepare one deterministic running-state observation. # C: O(1)
    pub(crate) fn new() -> Self {
        let generation = NEXT_RUNNING_OBSERVER.fetch_add(1, Ordering::AcqRel);
        Self { generation, released: false }
    }

    /// Monotonic identity for the requester thread. # C: O(1)
    pub(crate) fn generation(&self) -> u64 { self.generation }

    /// Release the paused requester. # C: O(1)
    pub(crate) fn release(&mut self) {
        RELEASED_RUNNING_OBSERVER.fetch_max(self.generation, Ordering::Release);
        self.released = true;
    }
}

impl Drop for RunningObserverRelease {
    fn drop(&mut self) {
        if !self.released {
            RELEASED_RUNNING_OBSERVER.fetch_max(self.generation, Ordering::Release);
        }
    }
}

/// Arm this requester thread to pause after loading the running state. # C: O(1)
pub(crate) fn arm_running_observer(generation: u64) {
    PAUSE_ON_RUNNING.with(|armed| armed.set(generation));
    MARK_IDLE_ACQUIRE.with(|armed| armed.set(generation));
}

/// Wait until the requester has loaded the running state. # C: O(wait)
pub(crate) fn wait_running_observed(generation: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while RUNNING_OBSERVED.load(Ordering::Acquire) < generation {
        if std::time::Instant::now() >= deadline { return false; }
        std::thread::yield_now();
    }
    true
}

/// True when the armed requester acquired ownership after its retry. # C: O(1)
pub(crate) fn idle_acquire_was_marked(generation: u64) -> bool {
    IDLE_ACQUIRE_MARKED.load(Ordering::Acquire) >= generation
}
