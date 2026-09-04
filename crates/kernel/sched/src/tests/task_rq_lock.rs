// Stable task/runqueue locking and scheduler-change transaction contract.
//
// Production wiring lands in `live`; this hosted model pins the concurrency
// semantics independently so implementation work cannot weaken the contract to
// fit whichever lock API happens to exist. Every race is rendezvoused with
// channels: no sleeps, yields, or probabilistic stress loops decide an outcome.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::vec;
use std::vec::Vec;

const SRC: usize = 0;
const DST: usize = 1;
const TID: u32 = 41;
const FAIR: u8 = 1;
const RT: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    tid: u32,
    class: u8,
}

struct ModelRq {
    cpu: usize,
    queue: Mutex<Vec<Entry>>,
}

impl ModelRq {
    fn new(cpu: usize) -> Self { Self { cpu, queue: Mutex::new(Vec::new()) } }
    fn lock(&self) -> MutexGuard<'_, Vec<Entry>> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }
}

struct ModelTask {
    tid: u32,
    cpu: AtomicUsize,
    migrating: AtomicBool,
    class: AtomicU8,
    pi_lock: Mutex<()>,
}

impl ModelTask {
    fn new(cpu: usize) -> Self {
        Self {
            tid: TID, cpu: AtomicUsize::new(cpu), migrating: AtomicBool::new(false),
            class: AtomicU8::new(FAIR), pi_lock: Mutex::new(()),
        }
    }
    fn lock_pi(&self) -> MutexGuard<'_, ()> {
        self.pi_lock.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn model() -> (Arc<ModelTask>, Arc<Vec<Arc<ModelRq>>>) {
    let task = Arc::new(ModelTask::new(SRC));
    let rqs = Arc::new(vec![Arc::new(ModelRq::new(SRC)), Arc::new(ModelRq::new(DST))]);
    rqs[SRC].lock().push(Entry { tid: task.tid, class: FAIR });
    (task, rqs)
}

fn owner(rqs: &[Arc<ModelRq>], tid: u32) -> Option<usize> {
    let mut found = None;
    for rq in rqs {
        if rq.lock().iter().any(|e| e.tid == tid) {
            assert!(found.is_none(), "model task appears in two runqueues");
            found = Some(rq.cpu);
        }
    }
    found
}

fn entry(rqs: &[Arc<ModelRq>], cpu: usize, tid: u32) -> Option<Entry> {
    rqs[cpu].lock().iter().copied().find(|e| e.tid == tid)
}

/// Queued migration publishes Migrating before changing CPU and clears it only
/// after destination enqueue. It intentionally does not take TaskPi: stable
/// lookup must survive a runqueue-owned migration concurrent with its first
/// CPU read.
fn migrate(task: &ModelTask, rqs: &[Arc<ModelRq>], dst: usize) {
    let src = task.cpu.load(Ordering::Acquire);
    let mut src_q = rqs[src].lock();
    task.migrating.store(true, Ordering::Release);
    let pos = src_q.iter().position(|e| e.tid == task.tid).expect("source owns task");
    let item = src_q.remove(pos);
    task.cpu.store(dst, Ordering::Release);
    drop(src_q);
    rqs[dst].lock().push(item);
    task.migrating.store(false, Ordering::Release);
}

/// Positive-control algorithm: read CPU, then lock it, without revalidation.
fn legacy_lookup_then_lock<F>(task: &ModelTask, rqs: &[Arc<ModelRq>], seam: F) -> usize
where F: FnOnce() {
    let _pi = task.lock_pi();
    let cpu = task.cpu.load(Ordering::Acquire);
    seam();
    let _rq = rqs[cpu].lock();
    cpu
}

/// TaskPi -> candidate runqueue -> CPU/Migrating validation -> retry.
fn stable_rq_lock<R, S, X, F>(task: &ModelTask, rqs: &[Arc<ModelRq>],
                              mut seam: S, mut rejected: X, body: F) -> R
where
    S: FnMut(usize, usize),
    X: FnMut(usize),
    F: FnOnce(usize, MutexGuard<'_, Vec<Entry>>) -> R,
{
    let mut attempt = 0;
    loop {
        let pi = task.lock_pi();
        let cpu = task.cpu.load(Ordering::Acquire);
        seam(attempt, cpu);
        let rq = rqs[cpu].lock();
        if task.cpu.load(Ordering::Acquire) == cpu
            && !task.migrating.load(Ordering::Acquire)
        {
            return body(cpu, rq);
        }
        drop(rq);
        drop(pi);
        rejected(attempt);
        attempt += 1;
    }
}

struct Change<'a> {
    task: &'a ModelTask,
    queue: MutexGuard<'a, Vec<Entry>>,
    was_queued: bool,
}

impl<'a> Change<'a> {
    fn begin(task: &'a ModelTask, mut queue: MutexGuard<'a, Vec<Entry>>) -> Self {
        let pos = queue.iter().position(|e| e.tid == task.tid);
        let was_queued = pos.is_some();
        if let Some(pos) = pos { queue.remove(pos); }
        Self { task, queue, was_queued }
    }
    fn set_class(&self, class: u8) { self.task.class.store(class, Ordering::Release); }
}

impl Drop for Change<'_> {
    fn drop(&mut self) {
        if self.was_queued {
            self.queue.push(Entry {
                tid: self.task.tid,
                class: self.task.class.load(Ordering::Acquire),
            });
        }
    }
}

fn sched_change<R, F>(task: &ModelTask, rqs: &[Arc<ModelRq>], body: F) -> R
where F: FnOnce(&Change<'_>) -> R {
    stable_rq_lock(task, rqs, |_, _| {}, |_| {}, |_, queue| {
        let change = Change::begin(task, queue);
        body(&change)
    })
}

#[test]
fn positive_control_lookup_then_lock_can_lock_the_pre_migration_rq() {
    let (task, rqs) = model();
    let (looked_tx, looked_rx) = mpsc::channel();
    let (moved_tx, moved_rx) = mpsc::channel();
    let mover_task = Arc::clone(&task);
    let mover_rqs = Arc::clone(&rqs);
    let mover = std::thread::spawn(move || {
        looked_rx.recv().expect("lookup checkpoint");
        migrate(&mover_task, &mover_rqs, DST);
        moved_tx.send(()).expect("migration completion");
    });

    let locked = legacy_lookup_then_lock(&task, &rqs, || {
        looked_tx.send(()).expect("publish lookup");
        moved_rx.recv().expect("wait for migration");
    });
    mover.join().expect("mover completed");

    assert_eq!(locked, SRC, "positive control no longer models lookup-then-lock");
    assert_eq!(task.cpu.load(Ordering::Acquire), DST);
    assert_eq!(owner(&rqs, TID), Some(DST));
}

#[test]
fn stable_lock_retries_and_selects_the_post_migration_rq() {
    let (task, rqs) = model();
    let (looked_tx, looked_rx) = mpsc::channel();
    let (moved_tx, moved_rx) = mpsc::channel();
    let mover_task = Arc::clone(&task);
    let mover_rqs = Arc::clone(&rqs);
    let mover = std::thread::spawn(move || {
        looked_rx.recv().expect("lookup checkpoint");
        migrate(&mover_task, &mover_rqs, DST);
        moved_tx.send(()).expect("migration completion");
    });
    let mut attempts = Vec::new();

    let locked = stable_rq_lock(&task, &rqs, |attempt, cpu| {
        attempts.push((attempt, cpu));
        if attempt == 0 {
            looked_tx.send(()).expect("publish first lookup");
            moved_rx.recv().expect("wait for migration");
        }
    }, |_| {}, |cpu, queue| {
        assert!(queue.iter().any(|e| e.tid == TID), "locked rq does not own task");
        cpu
    });
    mover.join().expect("mover completed");

    assert_eq!(attempts, vec![(0, SRC), (1, DST)]);
    assert_eq!(locked, DST);
}

#[test]
fn migrating_marker_forces_rejection_even_when_cpu_is_unchanged() {
    let (task, rqs) = model();
    task.migrating.store(true, Ordering::Release);
    let rejected = AtomicUsize::new(0);

    let locked = stable_rq_lock(&task, &rqs, |_, _| {}, |attempt| {
        assert_eq!(attempt, 0);
        rejected.fetch_add(1, Ordering::Relaxed);
        task.migrating.store(false, Ordering::Release);
    }, |cpu, _| cpu);

    assert_eq!(locked, SRC);
    assert_eq!(rejected.load(Ordering::Relaxed), 1,
        "Migrating was not observed as a retry condition");
}

#[test]
fn change_holds_the_rq_lock_across_dequeue_mutate_and_reenqueue() {
    let (task, rqs) = model();
    sched_change(&task, &rqs, |change| {
        assert!(!change.queue.iter().any(|e| e.tid == TID),
            "dequeue did not remove task from the locked runqueue");
        assert_eq!(owner_without(&rqs, TID, SRC), None, "dequeue did not remove task");
        assert!(rqs[SRC].queue.try_lock().is_err(),
            "runqueue became observable between dequeue and enqueue");
        change.set_class(RT);
    });

    assert_eq!(owner(&rqs, TID), Some(SRC));
    assert_eq!(entry(&rqs, SRC, TID).map(|e| e.class), Some(RT));
}

/// Query every runqueue except the one deliberately locked by this thread.
fn owner_without(rqs: &[Arc<ModelRq>], tid: u32, excluded: usize) -> Option<usize> {
    rqs.iter().filter(|rq| rq.cpu != excluded)
        .find(|rq| rq.lock().iter().any(|e| e.tid == tid)).map(|rq| rq.cpu)
}

#[test]
fn change_reenqueues_during_unwind_before_releasing_locks() {
    let (task, rqs) = model();
    let result = catch_unwind(AssertUnwindSafe(|| {
        sched_change(&task, &rqs, |change| {
            change.set_class(RT);
            panic!("injected mutation failure");
        });
    }));

    assert!(result.is_err(), "positive-control panic did not unwind");
    assert_eq!(owner(&rqs, TID), Some(SRC), "unwind stranded runnable task");
    assert_eq!(entry(&rqs, SRC, TID).map(|e| e.class), Some(RT));
    if matches!(task.pi_lock.try_lock(), Err(TryLockError::WouldBlock)) {
        panic!("unwind retained TaskPi");
    }
    if matches!(rqs[SRC].queue.try_lock(), Err(TryLockError::WouldBlock)) {
        panic!("unwind retained runqueue lock");
    }
}

#[test]
fn change_does_not_enqueue_a_task_that_started_unqueued() {
    let (task, rqs) = model();
    rqs[SRC].lock().clear();

    sched_change(&task, &rqs, |change| change.set_class(RT));

    assert_eq!(owner(&rqs, TID), None);
    assert_eq!(task.class.load(Ordering::Acquire), RT);
}
