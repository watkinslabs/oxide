// Host-thread realisation of the socket sleep queue. A host build has no
// kernel runqueue to park a task on, so the queue parks the calling OS thread
// instead: each waiter publishes its own wake flag under the queue lock, and
// the yield step spins-with-yield on that flag until it is set or the deadline
// passes. The state machine — publish-then-drop-then-yield-then-retire, FIFO
// single wake, drain-on-wake-all — is the same one the kernel realisation
// implements, so call sites are written once.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::sock_clock::{deadline_expired, monotonic_ns_safe};

/// One waiter's wake flag. Held by the queue while parked and by the waiter
/// for the duration of the yield.
type WakeFlag = Arc<AtomicBool>;

std::thread_local! {
    /// The flag this thread published, and the expiry it published with. One
    /// entry: a thread parks on at most one queue at a time, the same
    /// invariant the kernel realisation relies on (a task has one state).
    static PARKED: RefCell<Option<(usize, WakeFlag, u64)>> = const { RefCell::new(None) };
}

/// # C: O(1) park / O(N_waiters) wake
pub struct SockWaitQueue {
    waiters: std::sync::Mutex<Vec<WakeFlag>>,
}

impl SockWaitQueue {
    /// # C: O(1)
    pub const fn new() -> Self { Self { waiters: std::sync::Mutex::new(Vec::new()) } }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<WakeFlag>> {
        self.waiters.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn key(&self) -> usize { self as *const Self as usize }

    /// Publish the calling thread on this queue with an optional expiry.
    /// `0` disables the expiry.
    /// # SAFETY: signature parity with the kernel realisation, whose park
    /// requires process context and a held resource lock; nothing here relies
    /// on that beyond the same publish-before-unlock ordering.
    /// # C: O(1)
    pub unsafe fn park_interruptible_with_deadline(&self, deadline_ns: u64) {
        let flag: WakeFlag = Arc::new(AtomicBool::new(false));
        self.lock().push(flag.clone());
        let key = self.key();
        PARKED.with(|p| *p.borrow_mut() = Some((key, flag, deadline_ns)));
    }

    /// Named lock-coupled interruptible publication with an absolute deadline.
    /// # SAFETY: see [`Self::park_interruptible_with_deadline`].
    /// # C: O(1)
    pub unsafe fn prepare_to_wait_interruptible_with_deadline(&self, deadline_ns: u64) {
        // SAFETY: preserves the hosted queue's publish-before-unlock ordering.
        unsafe { self.park_interruptible_with_deadline(deadline_ns); }
    }

    /// Yield until this thread's flag is set or its expiry passes.
    /// # SAFETY: signature parity with the kernel realisation; the caller must
    /// hold no lock a waker needs, exactly as on the kernel target.
    /// # C: O(wait)
    pub unsafe fn wait(&self) {
        let parked = PARKED.with(|p| p.borrow().clone());
        let Some((key, flag, deadline_ns)) = parked else { return };
        if key != self.key() { return; }
        while !flag.load(Ordering::Acquire) {
            if deadline_expired(deadline_ns) { break; }
            sync::relax();
        }
        self.remove_current();
    }

    /// Retire this thread's registration after wake, expiry, or cancellation.
    /// # C: O(N_waiters)
    pub fn remove_current(&self) {
        let parked = PARKED.with(|p| p.borrow_mut().take());
        let Some((key, flag, _)) = parked else { return };
        if key != self.key() {
            // Not ours: restore it so the owning queue can still retire it.
            PARKED.with(|p| *p.borrow_mut() = Some((key, flag, 0)));
            return;
        }
        self.lock().retain(|f| !Arc::ptr_eq(f, &flag));
    }

    /// # C: O(N_waiters)
    pub fn cancel_current_park(&self) { self.remove_current(); }

    /// Wake the longest-waiting thread (FIFO), if any.
    /// # C: O(1)
    pub fn wake_one(&self) {
        let mut g = self.lock();
        if g.is_empty() { return; }
        let f = g.remove(0);
        drop(g);
        f.store(true, Ordering::Release);
    }

    /// # C: O(N_waiters)
    pub fn wake_all(&self) {
        let drained: Vec<WakeFlag> = {
            let mut g = self.lock();
            if g.is_empty() { return; }
            g.drain(..).collect()
        };
        for f in drained { f.store(true, Ordering::Release); }
    }

    /// # C: O(1)
    pub fn has_waiters(&self) -> bool { !self.lock().is_empty() }
}

impl Default for SockWaitQueue {
    fn default() -> Self { Self::new() }
}

/// Nanoseconds from now, as an absolute expiry this queue accepts.
/// # C: O(1)
pub fn deadline_in_ns(delta_ns: u64) -> u64 { monotonic_ns_safe().saturating_add(delta_ns) }
