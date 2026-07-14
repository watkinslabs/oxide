use core::sync::atomic::{AtomicU64, Ordering};

pub(super) trait GenerationAtomic {
    fn load_acquire(&self) -> u64;
    fn advance_release(&self);
    fn consume(&self, current: u64, published: u64) -> Result<(), u64>;
}

impl GenerationAtomic for AtomicU64 {
    fn load_acquire(&self) -> u64 { self.load(Ordering::Acquire) }
    fn advance_release(&self) { self.fetch_add(1, Ordering::Release); }
    fn consume(&self, current: u64, published: u64) -> Result<(), u64> {
        self.compare_exchange(current, published, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
    }
}

/// Monotonic publication state shared by final-drop and reaper paths.
pub(super) struct PendingSignal<A> {
    published: A,
    consumed: A,
}

impl PendingSignal<AtomicU64> {
    pub(super) const fn new() -> Self {
        Self { published: AtomicU64::new(0), consumed: AtomicU64::new(0) }
    }
}

impl<A: GenerationAtomic> PendingSignal<A> {
    /// Publish work before raising the reaper softirq. # C: O(1)
    pub(super) fn publish(&self) { self.published.advance_release(); }

    /// Claim every publication visible at one linearization point. # C: O(contention)
    pub(super) fn harvest(&self) -> bool {
        loop {
            let published = self.published.load_acquire();
            let consumed = self.consumed.load_acquire();
            if published == consumed { return false; }
            if self.consumed.consume(consumed, published).is_ok() { return true; }
        }
    }

    /// Close publication racing with wait-list arm before schedule. # C: O(1)
    pub(super) fn published_after_arm(&self) -> bool {
        self.published.load_acquire() != self.consumed.load_acquire()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_publication_coalesces_until_harvest() {
        let pending = PendingSignal::new();
        pending.publish();
        pending.publish();
        assert!(pending.harvest());
        assert!(!pending.harvest());
    }

    #[test]
    fn post_arm_check_observes_unconsumed_publication() {
        let pending = PendingSignal::new();
        assert!(!pending.published_after_arm());
        pending.publish();
        assert!(pending.published_after_arm());
        assert!(pending.harvest());
        assert!(!pending.published_after_arm());
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use super::{GenerationAtomic, PendingSignal};
    use loom::sync::atomic::{AtomicU64, Ordering};
    use loom::sync::{Arc, Mutex};
    use loom::thread;

    struct LoomGeneration(AtomicU64);

    impl LoomGeneration {
        fn new(value: u64) -> Self { Self(AtomicU64::new(value)) }
    }

    impl GenerationAtomic for LoomGeneration {
        fn load_acquire(&self) -> u64 { self.0.load(Ordering::Acquire) }
        fn advance_release(&self) { self.0.fetch_add(1, Ordering::Release); }
        fn consume(&self, current: u64, published: u64) -> Result<(), u64> {
            self.0.compare_exchange(current, published, Ordering::AcqRel, Ordering::Acquire)
                .map(|_| ())
        }
    }

    fn pending() -> PendingSignal<LoomGeneration> {
        PendingSignal {
            published: LoomGeneration::new(0), consumed: LoomGeneration::new(0),
        }
    }

    #[test]
    fn concurrent_publications_coalesce_until_harvest() {
        loom::model(|| {
            let pending = Arc::new(pending());
            let one = {
                let pending = Arc::clone(&pending);
                thread::spawn(move || pending.publish())
            };
            let two = {
                let pending = Arc::clone(&pending);
                thread::spawn(move || pending.publish())
            };
            one.join().unwrap();
            two.join().unwrap();
            assert!(pending.harvest());
            assert!(!pending.harvest());
        });
    }

    #[test]
    fn racing_harvesters_claim_a_generation_once() {
        loom::model(|| {
            let pending = Arc::new(pending());
            pending.publish();
            let one = {
                let pending = Arc::clone(&pending);
                thread::spawn(move || pending.harvest())
            };
            let two = {
                let pending = Arc::clone(&pending);
                thread::spawn(move || pending.harvest())
            };
            assert_ne!(one.join().unwrap(), two.join().unwrap());
            assert!(!pending.harvest());
        });
    }

    #[test]
    fn post_arm_check_prevents_lost_reaper_wakeup() {
        loom::model(|| {
            let pending = Arc::new(pending());
            let armed = Arc::new(Mutex::new(false));
            let producer = {
                let pending = Arc::clone(&pending);
                let armed = Arc::clone(&armed);
                thread::spawn(move || {
                    pending.publish();
                    let mut armed = armed.lock().unwrap();
                    if *armed { *armed = false; true } else { false }
                })
            };
            let reaper = {
                let pending = Arc::clone(&pending);
                let armed = Arc::clone(&armed);
                thread::spawn(move || {
                    let harvested = pending.harvest();
                    *armed.lock().unwrap() = true;
                    let cancelled = pending.published_after_arm();
                    if cancelled { *armed.lock().unwrap() = false; }
                    (harvested, cancelled)
                })
            };

            let woken = producer.join().unwrap();
            let (harvested, cancelled) = reaper.join().unwrap();
            assert!(harvested || cancelled || woken);
        });
    }
}
