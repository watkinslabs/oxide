use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use super::gc;

static PASS_PAUSED: AtomicBool = AtomicBool::new(false);
static RELEASE_PASS: AtomicBool = AtomicBool::new(false);
static PENDING_MARKED: AtomicBool = AtomicBool::new(false);

std::thread_local! {
    static PAUSE_THIS_COLLECTOR: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    static PANIC_AFTER_PAUSE: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    static MARK_PENDING_REQUEST: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    static PAUSE_ON_RUNNING: core::cell::RefCell<Option<RunningObserver>> = const { core::cell::RefCell::new(None) };
    static MARK_IDLE_ACQUIRE: core::cell::RefCell<Option<RunningObserver>> = const { core::cell::RefCell::new(None) };
}

/// Pause the armed collector after one owned pass. # C: O(wait)
pub(super) fn pause_after_pass() {
    if !PAUSE_THIS_COLLECTOR.with(|armed| armed.replace(false)) { return; }
    PASS_PAUSED.store(true, Ordering::Release);
    crate::hosted_fixture::spin_until("the GC pass is released",
        || RELEASE_PASS.load(Ordering::Acquire));
    PASS_PAUSED.store(false, Ordering::Release);
    if PANIC_AFTER_PAUSE.with(|armed| armed.replace(false)) {
        panic!("injected collector owner unwind");
    }
}

/// Pause an armed requester after it observes a running owner. # C: O(wait)
pub(super) fn pause_after_observing_running(state: u8) {
    let observer = PAUSE_ON_RUNNING.with(|armed| armed.borrow_mut().take());
    let Some(observer) = observer else { return };
    if state != 1 { return; }
    observer.state.observed.store(true, Ordering::Release);
    while !observer.state.released.load(Ordering::Acquire) {
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
    let observer = MARK_IDLE_ACQUIRE.with(|armed| armed.borrow_mut().take());
    if let Some(observer) = observer { observer.state.idle_acquire.store(true, Ordering::Release); }
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

struct RunningObserverState {
    observed: AtomicBool,
    released: AtomicBool,
    idle_acquire: AtomicBool,
}

#[derive(Clone)]
pub(crate) struct RunningObserver { state: Arc<RunningObserverState> }

impl RunningObserver {
    /// Wait until this requester has loaded the running state. # C: O(wait)
    pub(crate) fn wait_observed(&self) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !self.state.observed.load(Ordering::Acquire) {
            if std::time::Instant::now() >= deadline { return false; }
            std::thread::yield_now();
        }
        true
    }

    /// True when this requester acquired ownership after its retry. # C: O(1)
    pub(crate) fn idle_acquire_was_marked(&self) -> bool {
        self.state.idle_acquire.load(Ordering::Acquire)
    }

    /// True when this exact requester has been released. # C: O(1)
    pub(crate) fn is_released(&self) -> bool { self.state.released.load(Ordering::Acquire) }
}

/// RAII release for one requester paused after observing a running owner.
pub(crate) struct RunningObserverRelease { observer: RunningObserver, released: bool }

impl RunningObserverRelease {
    /// Prepare one deterministic running-state observation. # C: O(1)
    pub(crate) fn new() -> Self {
        let state = Arc::new(RunningObserverState { observed: AtomicBool::new(false),
            released: AtomicBool::new(false), idle_acquire: AtomicBool::new(false) });
        Self { observer: RunningObserver { state }, released: false }
    }

    /// Exact identity for the requester thread. # C: O(1)
    pub(crate) fn requester(&self) -> RunningObserver { self.observer.clone() }

    /// Wait until this requester has loaded the running state. # C: O(wait)
    pub(crate) fn wait_observed(&self) -> bool { self.observer.wait_observed() }

    /// Release the paused requester. # C: O(1)
    pub(crate) fn release(&mut self) {
        self.observer.state.released.store(true, Ordering::Release);
        self.released = true;
    }
}

impl Drop for RunningObserverRelease {
    fn drop(&mut self) {
        if !self.released {
            self.observer.state.released.store(true, Ordering::Release);
        }
    }
}

/// Arm this requester thread to pause after loading the running state. # C: O(1)
pub(crate) fn arm_running_observer(observer: &RunningObserver) {
    PAUSE_ON_RUNNING.with(|armed| *armed.borrow_mut() = Some(observer.clone()));
    MARK_IDLE_ACQUIRE.with(|armed| *armed.borrow_mut() = Some(observer.clone()));
}
