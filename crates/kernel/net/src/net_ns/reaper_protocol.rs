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
    use network_namespace::{LoomFinalDropCompleted, LoomRegistryEntry, LoomWeakOwner};

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

    #[derive(Copy, Clone, Debug)]
    enum RetentionBoundary {
        MaterializedState, SocketFile, PassedSocket, NamespaceFd,
        PidfdTarget, ListnsSnapshot, BlockedIo, IngressLease,
    }

    const RETENTION_BOUNDARIES: [RetentionBoundary; 8] = [
        RetentionBoundary::MaterializedState, RetentionBoundary::SocketFile,
        RetentionBoundary::PassedSocket, RetentionBoundary::NamespaceFd,
        RetentionBoundary::PidfdTarget, RetentionBoundary::ListnsSnapshot,
        RetentionBoundary::BlockedIo, RetentionBoundary::IngressLease,
    ];

    #[derive(Clone)]
    struct FinalDrop {
        completed: Arc<loom::sync::atomic::AtomicBool>,
        pending: Arc<PendingSignal<LoomGeneration>>,
    }

    impl LoomFinalDropCompleted for FinalDrop {
        fn completed(&self) -> bool { self.completed.load(Ordering::Acquire) }
    }

    struct OwnerRefs {
        strong: AtomicU64,
        final_drop: FinalDrop,
    }

    struct Owner { refs: Arc<OwnerRefs> }

    #[derive(Clone)]
    struct WeakOwner { refs: Arc<OwnerRefs> }

    impl Owner {
        fn new(pending: Arc<PendingSignal<LoomGeneration>>) -> (Self, WeakOwner, FinalDrop) {
            let final_drop = FinalDrop {
                completed: Arc::new(loom::sync::atomic::AtomicBool::new(false)), pending,
            };
            let refs = Arc::new(OwnerRefs {
                strong: AtomicU64::new(1), final_drop: final_drop.clone(),
            });
            (Self { refs: Arc::clone(&refs) }, WeakOwner { refs }, final_drop)
        }
    }

    impl Clone for Owner {
        fn clone(&self) -> Self {
            self.refs.strong.fetch_add(1, Ordering::Relaxed);
            Self { refs: Arc::clone(&self.refs) }
        }
    }

    impl Drop for Owner {
        fn drop(&mut self) {
            if self.refs.strong.fetch_sub(1, Ordering::Release) == 1 {
                self.refs.final_drop.completed.store(true, Ordering::Release);
                self.refs.final_drop.pending.publish();
            }
        }
    }

    impl LoomWeakOwner for WeakOwner {
        type Strong = Owner;

        fn upgrade(&self) -> Option<Self::Strong> {
            let mut count = self.refs.strong.load(Ordering::Acquire);
            loop {
                if count == 0 { return None; }
                match self.refs.strong.compare_exchange_weak(count, count + 1,
                    Ordering::Acquire, Ordering::Relaxed)
                {
                    Ok(_) => return Some(Owner { refs: Arc::clone(&self.refs) }),
                    Err(observed) => count = observed,
                }
            }
        }
    }

    fn model_composed_retention(boundary: RetentionBoundary) {
        loom::model(move || {
            let pending = Arc::new(pending());
            let (root, weak, final_drop) = Owner::new(Arc::clone(&pending));
            let holder = Arc::new(Mutex::new(Some(root.clone())));
            let entry = Arc::new(Mutex::new(LoomRegistryEntry::Live {
                owner: weak, final_drop,
            }));
            drop(root);

            let (acquired_tx, acquired_rx) = loom::sync::mpsc::channel();
            let (release_tx, release_rx) = loom::sync::mpsc::channel();
            let operation_holder = Arc::clone(&holder);
            let operation = thread::spawn(move || {
                let retained = operation_holder.lock().unwrap().as_ref().cloned();
                acquired_tx.send(retained.is_some()).unwrap();
                if retained.is_some() { release_rx.recv().unwrap(); }
                drop(retained);
            });
            let close_holder = Arc::clone(&holder);
            let close = thread::spawn(move || drop(close_holder.lock().unwrap().take()));
            let reaper_pending = Arc::clone(&pending);
            let reaper_entry = Arc::clone(&entry);
            let reaper = thread::spawn(move || {
                let harvested = reaper_pending.harvest();
                let claimed = harvested
                    && reaper_entry.lock().unwrap().claim_if_completed();
                (harvested, claimed)
            });

            let acquired = acquired_rx.recv().unwrap();
            close.join().unwrap();
            let (first_harvest, first_claim) = reaper.join().unwrap();
            assert_eq!(first_harvest, first_claim,
                "{boundary:?} cannot consume final-drop work without its claim");
            if acquired {
                assert!(!first_claim, "{boundary:?} claimed an active operation");
                let pin = entry.lock().unwrap().lookup()
                    .expect("retained operation must keep registry lookup live");
                release_tx.send(()).unwrap();
                operation.join().unwrap();
                assert!(!pending.harvest(), "{boundary:?} published before lookup pin release");
                drop(pin);
            } else {
                operation.join().unwrap();
            }
            let late_harvest = pending.harvest();
            let late_claim = late_harvest && entry.lock().unwrap().claim_if_completed();
            assert_ne!(first_claim, late_claim,
                "{boundary:?} must have exactly one harvest/claim winner");
            assert!(entry.lock().unwrap().is_claimed());
            assert!(entry.lock().unwrap().lookup().is_none());
            assert!(!pending.harvest());
            assert!(!entry.lock().unwrap().claim_if_completed());
        });
    }

    #[test]
    fn every_retention_boundary_composes_with_reaper_publication() {
        for boundary in RETENTION_BOUNDARIES { model_composed_retention(boundary); }
    }
}
