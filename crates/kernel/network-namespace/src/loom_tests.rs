use core::sync::atomic::Ordering;
use loom::sync::atomic::{AtomicBool, AtomicUsize};
use loom::sync::mpsc;
use loom::sync::{Arc, Mutex};
use loom::thread;

use crate::callback::{install_transition, published, InstallError};
use crate::registry::{FinalDropCompleted, RegistryEntry, WeakOwner};

const CALLBACK_NONE: usize = 0;
const CALLBACK_ONE: usize = 1;
const CALLBACK_TWO: usize = 2;
#[derive(Clone)]
struct ModelWeak { owners: Arc<AtomicUsize> }

struct ModelOwner { owners: Arc<AtomicUsize> }

impl ModelOwner {
    fn new() -> (Self, ModelWeak) {
        let owners = Arc::new(AtomicUsize::new(1));
        (Self { owners: Arc::clone(&owners) }, ModelWeak { owners })
    }
}

impl Clone for ModelOwner {
    fn clone(&self) -> Self {
        self.owners.fetch_add(1, Ordering::Relaxed);
        Self { owners: Arc::clone(&self.owners) }
    }
}

impl Drop for ModelOwner {
    fn drop(&mut self) { self.owners.fetch_sub(1, Ordering::Release); }
}

impl WeakOwner for ModelWeak {
    type Strong = ModelOwner;

    fn upgrade(&self) -> Option<Self::Strong> {
        let mut count = self.owners.load(Ordering::Acquire);
        loop {
            if count == 0 { return None; }
            match self.owners.compare_exchange_weak(count, count + 1,
                Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return Some(ModelOwner { owners: Arc::clone(&self.owners) }),
                Err(observed) => count = observed,
            }
        }
    }
}

#[derive(Clone)]
struct ModelPublication { completed: Arc<AtomicBool> }

impl ModelPublication {
    fn new() -> Self { Self { completed: Arc::new(AtomicBool::new(false)) } }
    fn publish(&self) { self.completed.store(true, Ordering::Release); }
}

impl FinalDropCompleted for ModelPublication {
    fn completed(&self) -> bool { self.completed.load(Ordering::Acquire) }
}

fn install(slot: &AtomicUsize, value: usize) -> Result<(), InstallError> {
    install_transition(CALLBACK_NONE, value,
        |null, value, success, failure| slot.compare_exchange(null, value, success, failure))
}

#[test]
fn callback_install_and_final_notification_are_linearizable() {
    loom::model(|| {
        let slot = Arc::new(AtomicUsize::new(CALLBACK_NONE));
        let install_slot = Arc::clone(&slot);
        let installer = thread::spawn(move || install(&install_slot, CALLBACK_ONE));
        let allocate_slot = Arc::clone(&slot);
        let allocator = thread::spawn(move || {
            published(CALLBACK_NONE, allocate_slot.load(Ordering::Acquire))
        });
        assert_eq!(installer.join().unwrap(), Ok(()));
        if let Some(callback) = allocator.join().unwrap() {
            assert_eq!(callback, CALLBACK_ONE,
                "a successful allocation can only retain the installed callback");
        }
        assert_eq!(slot.load(Ordering::Acquire), CALLBACK_ONE);
        assert_eq!(published(CALLBACK_NONE, slot.load(Ordering::Acquire)), Some(CALLBACK_ONE),
            "every post-install allocation has a final-drop notifier");
    });
}

#[test]
fn competing_callback_install_preserves_one_immutable_value() {
    loom::model(|| {
        let slot = Arc::new(AtomicUsize::new(CALLBACK_NONE));
        let one_slot = Arc::clone(&slot);
        let one = thread::spawn(move || install(&one_slot, CALLBACK_ONE));
        let two_slot = Arc::clone(&slot);
        let two = thread::spawn(move || install(&two_slot, CALLBACK_TWO));
        let one_result = one.join().unwrap();
        let two_result = two.join().unwrap();
        let value = slot.load(Ordering::Acquire);
        assert!(matches!(value, CALLBACK_ONE | CALLBACK_TWO));
        assert_eq!(one_result == Ok(()), value == CALLBACK_ONE);
        assert_eq!(two_result == Ok(()), value == CALLBACK_TWO);
    });
}

#[test]
fn lookup_drop_and_claim_never_resurrect_claimed_entry() {
    loom::model(|| {
        let (owner, weak) = ModelOwner::new();
        let publication = ModelPublication::new();
        let entry = Arc::new(Mutex::new(RegistryEntry::Live {
            owner: weak, final_drop: publication.clone(),
        }));
        let lookup_entry = Arc::clone(&entry);
        let lookup = thread::spawn(move || lookup_entry.lock().unwrap().lookup());
        let claim_entry = Arc::clone(&entry);
        let claim = thread::spawn(move || {
            drop(owner);
            publication.publish();
            claim_entry.lock().unwrap().claim_if_completed()
        });
        let pin = lookup.join().unwrap();
        let first_claim = claim.join().unwrap();
        drop(pin);
        let mut entry = entry.lock().unwrap();
        let second_claim = entry.claim_if_completed();
        assert!(first_claim || second_claim);
        assert!(!entry.claim_if_completed());
        assert!(entry.lookup().is_none());
        assert!(entry.is_claimed());
    });
}

#[test]
fn another_notification_cannot_claim_an_in_progress_final_drop() {
    loom::model(|| {
        let (first_owner, first_weak) = ModelOwner::new();
        let first_publication = ModelPublication::new();
        let first_entry = Arc::new(Mutex::new(RegistryEntry::Live {
            owner: first_weak, final_drop: first_publication.clone(),
        }));
        let (second_owner, second_weak) = ModelOwner::new();
        let second_publication = ModelPublication::new();
        let second_entry = Arc::new(Mutex::new(RegistryEntry::Live {
            owner: second_weak, final_drop: second_publication.clone(),
        }));
        let notifications = Arc::new(AtomicUsize::new(0));
        let (first_started, wait_for_first) = mpsc::channel();
        let (allow_first_completion, first_allowed) = mpsc::channel();
        let (second_notified, wait_for_second) = mpsc::channel();

        let first_notifications = Arc::clone(&notifications);
        let first_drop = thread::spawn(move || {
            drop(first_owner);
            first_started.send(()).unwrap();
            first_allowed.recv().unwrap();
            first_publication.publish();
            first_notifications.fetch_add(1, Ordering::Release);
        });
        let second_notifications = Arc::clone(&notifications);
        let second_drop = thread::spawn(move || {
            drop(second_owner);
            second_publication.publish();
            second_notifications.fetch_add(1, Ordering::Release);
            second_notified.send(()).unwrap();
        });

        wait_for_first.recv().unwrap();
        wait_for_second.recv().unwrap();
        assert_eq!(notifications.load(Ordering::Acquire), 1);
        assert!(first_entry.lock().unwrap().lookup().is_none());
        let first_claim = first_entry.lock().unwrap().claim_if_completed();
        let second_claim = second_entry.lock().unwrap().claim_if_completed();
        assert!(!first_claim,
            "another namespace notification cannot complete the first destructor");
        assert!(second_claim);
        allow_first_completion.send(()).unwrap();
        first_drop.join().unwrap();
        second_drop.join().unwrap();
        let first_late = first_entry.lock().unwrap().claim_if_completed();
        let second_late = second_entry.lock().unwrap().claim_if_completed();
        assert!(first_late);
        assert!(!second_late);
    });
}

#[derive(Copy, Clone, Debug)]
enum RetentionBoundary {
    MaterializedState,
    SocketFile,
    PassedSocket,
    NamespaceFd,
    PidfdTarget,
    ListnsSnapshot,
    BlockedIo,
    IngressLease,
}

const RETENTION_BOUNDARIES: [RetentionBoundary; 8] = [
    RetentionBoundary::MaterializedState,
    RetentionBoundary::SocketFile,
    RetentionBoundary::PassedSocket,
    RetentionBoundary::NamespaceFd,
    RetentionBoundary::PidfdTarget,
    RetentionBoundary::ListnsSnapshot,
    RetentionBoundary::BlockedIo,
    RetentionBoundary::IngressLease,
];

#[derive(Clone)]
struct MatrixWeak { refs: Arc<MatrixRefs> }

struct MatrixOwner { refs: Arc<MatrixRefs> }

struct MatrixRefs {
    strong: AtomicUsize,
    final_drop: ModelPublication,
}

impl MatrixOwner {
    fn new() -> (Self, MatrixWeak, ModelPublication) {
        let final_drop = ModelPublication::new();
        let refs = Arc::new(MatrixRefs {
            strong: AtomicUsize::new(1), final_drop: final_drop.clone(),
        });
        (Self { refs: Arc::clone(&refs) }, MatrixWeak { refs }, final_drop)
    }
}

impl Clone for MatrixOwner {
    fn clone(&self) -> Self {
        self.refs.strong.fetch_add(1, Ordering::Relaxed);
        Self { refs: Arc::clone(&self.refs) }
    }
}

impl Drop for MatrixOwner {
    fn drop(&mut self) {
        if self.refs.strong.fetch_sub(1, Ordering::Release) == 1 {
            self.refs.final_drop.publish();
        }
    }
}

impl WeakOwner for MatrixWeak {
    type Strong = MatrixOwner;

    fn upgrade(&self) -> Option<Self::Strong> {
        let mut count = self.refs.strong.load(Ordering::Acquire);
        loop {
            if count == 0 { return None; }
            match self.refs.strong.compare_exchange_weak(count, count + 1,
                Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return Some(MatrixOwner { refs: Arc::clone(&self.refs) }),
                Err(observed) => count = observed,
            }
        }
    }
}

fn model_retention_boundary(boundary: RetentionBoundary) {
    loom::model(move || {
        let (root, weak, final_drop) = MatrixOwner::new();
        let holder = Arc::new(Mutex::new(Some(root.clone())));
        let entry = Arc::new(Mutex::new(RegistryEntry::Live { owner: weak, final_drop }));
        drop(root);

        let (acquired_tx, acquired_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let operation_holder = Arc::clone(&holder);
        let operation = thread::spawn(move || {
            let retained = operation_holder.lock().unwrap().as_ref().cloned();
            acquired_tx.send(retained.is_some()).unwrap();
            if retained.is_some() { release_rx.recv().unwrap(); }
            drop(retained);
        });
        let close_holder = Arc::clone(&holder);
        let close = thread::spawn(move || drop(close_holder.lock().unwrap().take()));
        let claim_entry = Arc::clone(&entry);
        let claim = thread::spawn(move || claim_entry.lock().unwrap().claim_if_completed());

        let acquired = acquired_rx.recv().unwrap();
        close.join().unwrap();
        let first_claim = claim.join().unwrap();
        if acquired {
            assert!(!first_claim, "{boundary:?} claimed while retained operation was active");
            let pin = entry.lock().unwrap().lookup()
                .expect("retained operation must keep registry lookup live");
            release_tx.send(()).unwrap();
            operation.join().unwrap();
            assert!(!entry.lock().unwrap().claim_if_completed(),
                "{boundary:?} claimed while registry lookup pin was active");
            drop(pin);
            assert!(entry.lock().unwrap().claim_if_completed(),
                "{boundary:?} final release did not publish teardown");
        } else {
            operation.join().unwrap();
            let late_claim = entry.lock().unwrap().claim_if_completed();
            assert_ne!(first_claim, late_claim,
                "{boundary:?} final-drop-first schedule must have one claim winner");
        }
        assert!(entry.lock().unwrap().is_claimed());
        assert!(entry.lock().unwrap().lookup().is_none());
        assert!(!entry.lock().unwrap().claim_if_completed());
    });
}

#[test]
fn retained_owner_matrix_orders_every_boundary_against_final_drop() {
    for boundary in RETENTION_BOUNDARIES { model_retention_boundary(boundary); }
}
