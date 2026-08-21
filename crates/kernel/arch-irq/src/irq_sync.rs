//! In-flight hard-IRQ ownership shared by line and message-signalled sources.

use core::sync::atomic::{AtomicUsize, Ordering};

pub(crate) struct InFlight(AtomicUsize);

impl InFlight {
    pub(crate) const fn new() -> Self { Self(AtomicUsize::new(0)) }

    /// Publish one handler after its descriptor admitted dispatch. # C: O(1)
    pub(crate) fn enter(&self) -> InFlightGuard<'_> {
        self.0.fetch_add(1, Ordering::AcqRel);
        InFlightGuard(self)
    }

    /// Linux `synchronize_irq`: wait until every handler admitted before the
    /// source mask has left its hard-IRQ body. # C: waits for live handlers
    pub(crate) fn synchronize(&self) {
        while self.0.load(Ordering::Acquire) != 0 { core::hint::spin_loop(); }
    }

    /// Number of handlers admitted but not retired. # C: O(1)
    pub(crate) fn active(&self) -> usize { self.0.load(Ordering::Acquire) }
}

pub(crate) struct InFlightGuard<'a>(&'a InFlight);

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) { self.0.0.fetch_sub(1, Ordering::AcqRel); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};
    extern crate std;
    use std::sync::Arc;

    #[test]
    fn guard_tracks_exact_handler_lifetime() {
        let active = InFlight::new();
        assert_eq!(active.active(), 0);
        let first = active.enter();
        let second = active.enter();
        assert_eq!(active.active(), 2);
        drop(first);
        assert_eq!(active.active(), 1);
        drop(second);
        active.synchronize();
        assert_eq!(active.active(), 0);
    }

    #[test]
    fn synchronize_does_not_finish_before_an_admitted_handler_exits() {
        static ACTIVE: InFlight = InFlight::new();
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let entered_handler = Arc::clone(&entered);
        let release_handler = Arc::clone(&release);
        let handler = std::thread::spawn(move || {
            let _guard = ACTIVE.enter();
            entered_handler.store(true, Ordering::Release);
            while !release_handler.load(Ordering::Acquire) { std::thread::yield_now(); }
        });
        while !entered.load(Ordering::Acquire) { std::thread::yield_now(); }
        let done = Arc::new(AtomicBool::new(false));
        let sync_done = Arc::clone(&done);
        let waiter = std::thread::spawn(move || {
            ACTIVE.synchronize();
            sync_done.store(true, Ordering::Release);
        });
        std::thread::yield_now();
        assert!(!done.load(Ordering::Acquire));
        release.store(true, Ordering::Release);
        handler.join().unwrap();
        waiter.join().unwrap();
        assert!(done.load(Ordering::Acquire));
    }
}
