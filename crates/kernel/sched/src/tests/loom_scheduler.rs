//! Depth-eight models for the scheduler ownership protocols required by `13§15`.

use alloc::vec;
use alloc::vec::Vec;
use alloc::sync::Arc as ProductionArc;
use core::sync::atomic::Ordering;
use loom::sync::atomic::{AtomicBool, AtomicUsize};
use loom::sync::{Arc, Condvar, Mutex, MutexGuard};
use loom::thread;

use crate::{SchedClass, SchedPolicy, Task};
use crate::live::migration::{MovePoint, MoveResult, move_queued_with};
use crate::live::rq_locate::{SchedChange, StableTaskGuard, task_rq_lock_with};
use crate::live::runqueue::Runqueue;

const LOOM_DEPTH: usize = 8;

fn model(body: impl Fn() + Sync + Send + 'static) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(LOOM_DEPTH);
    builder.max_branches = 10_000;
    builder.check(body);
}

struct Signal { ready: Mutex<bool>, changed: Condvar }

impl Signal {
    fn new() -> Self { Self { ready: Mutex::new(false), changed: Condvar::new() } }
    fn publish(&self) {
        *self.ready.lock().unwrap() = true;
        self.changed.notify_all();
    }
    fn wait(&self) {
        let mut ready = self.ready.lock().unwrap();
        while !*ready { ready = self.changed.wait(ready).unwrap(); }
    }
}

struct Located {
    cpu: AtomicUsize,
    migrating: AtomicBool,
    lookup_read: Signal,
    migration_visible: Signal,
    migration_complete: Signal,
    pi: Mutex<()>,
    rq: [Mutex<bool>; 2],
}

/// Full `task_rq_lock` releases both locks before waiting for a switch-time
/// migration that needs TaskPi to install its destination ownership.
#[test]
fn task_rq_retry_drops_pi_and_finds_post_migration_owner() {
    model(|| {
        let task = Arc::new(Located {
            cpu: AtomicUsize::new(0), migrating: AtomicBool::new(false),
            lookup_read: Signal::new(), migration_visible: Signal::new(),
            migration_complete: Signal::new(),
            pi: Mutex::new(()), rq: [Mutex::new(true), Mutex::new(false)],
        });
        let moving = Arc::clone(&task);
        let mover = thread::spawn(move || {
            moving.lookup_read.wait();
            {
                let mut src = moving.rq[0].lock().unwrap();
                moving.migrating.store(true, Ordering::Release);
                *src = false;
            }
            moving.migration_visible.publish();
            let _pi = moving.pi.lock().unwrap();
            moving.cpu.store(1, Ordering::Release);
            *moving.rq[1].lock().unwrap() = true;
            moving.migrating.store(false, Ordering::Release);
            moving.migration_complete.publish();
        });
        let mut retries = 0;
        loop {
            let pi = task.pi.lock().unwrap();
            let cpu = task.cpu.load(Ordering::Acquire);
            task.lookup_read.publish();
            task.migration_visible.wait();
            let rq = task.rq[cpu].lock().unwrap();
            if task.cpu.load(Ordering::Acquire) == cpu
                && !task.migrating.load(Ordering::Acquire)
            {
                assert!(*rq, "stable lookup returned a runqueue without the task");
                break;
            }
            drop(rq);
            drop(pi);
            retries += 1;
            task.migration_complete.wait();
        }
        mover.join().unwrap();
        assert_eq!(retries, 1, "forced migration did not exercise the retry path");
        assert_eq!(task.cpu.load(Ordering::Acquire), 1);
    });
}

/// PI owner/donor/grant publication completes under the waiter lock; only
/// then may the waiter become runnable.
#[test]
fn pi_handoff_is_complete_before_wakeup() {
    model(|| {
        let state = Arc::new(Mutex::new((0usize, 0usize, false)));
        let runnable = Arc::new(AtomicBool::new(false));
        let writer_state = Arc::clone(&state);
        let writer_runnable = Arc::clone(&runnable);
        let unlock = thread::spawn(move || {
            let mut state = writer_state.lock().unwrap();
            state.0 = 7;
            state.1 = 11;
            state.2 = true;
            drop(state);
            writer_runnable.store(true, Ordering::Release);
        });
        let reader_state = Arc::clone(&state);
        let reader_runnable = Arc::clone(&runnable);
        let wake = thread::spawn(move || {
            while !reader_runnable.load(Ordering::Acquire) { thread::yield_now(); }
            let state = *reader_state.lock().unwrap();
            assert_eq!(state, (7, 11, true),
                "runnable waiter observed an incomplete PI handoff");
        });
        unlock.join().unwrap();
        wake.join().unwrap();
    });
}

struct QueueChange<'a> {
    queue: MutexGuard<'a, Option<usize>>,
    old: usize,
    replacement: Option<usize>,
}

impl<'a> QueueChange<'a> {
    fn begin(mut queue: MutexGuard<'a, Option<usize>>) -> Self {
        let old = queue.take().expect("model task starts queued");
        Self { queue, old, replacement: None }
    }
    fn replace(&mut self, value: usize) { self.replacement = Some(value); }
}

impl Drop for QueueChange<'_> {
    fn drop(&mut self) { *self.queue = Some(self.replacement.unwrap_or(self.old)); }
}

fn queue_restore(commit: bool) {
    model(move || {
        let entry = Arc::new(Mutex::new(Some(1usize)));
        let removed = Arc::new(AtomicBool::new(false));
        let writer_entry = Arc::clone(&entry);
        let writer_removed = Arc::clone(&removed);
        let writer = thread::spawn(move || {
            let mut change = QueueChange::begin(writer_entry.lock().unwrap());
            writer_removed.store(true, Ordering::Release);
            if commit { change.replace(2); }
        });
        let reader_entry = Arc::clone(&entry);
        let reader_removed = Arc::clone(&removed);
        let reader = thread::spawn(move || {
            while !reader_removed.load(Ordering::Acquire) { thread::yield_now(); }
            assert!(reader_entry.lock().unwrap().is_some(),
                "rq peer observed the dequeue/restore interior");
        });
        writer.join().unwrap();
        reader.join().unwrap();
        assert_eq!(*entry.lock().unwrap(), Some(if commit { 2 } else { 1 }));
    });
}

#[test]
fn queue_restoration_commit_is_atomic_to_rq_readers() { queue_restore(true); }

#[test]
fn queue_restoration_unwind_restores_exact_old_entry() { queue_restore(false); }

fn bridge_move(rqs: &[Mutex<Vec<usize>>; 2], task: usize, src: usize, dst: usize) {
    {
        let mut source = rqs[src].lock().unwrap();
        let at = source.iter().position(|id| *id == task).expect("source owns task");
        source.remove(at);
    }
    rqs[dst].lock().unwrap().push(task);
}

/// Opposing moves release the source before acquiring the destination. This
/// is the shipping one-rq-at-a-time equivalent of a canonical two-rq order.
#[test]
fn opposing_two_rq_moves_do_not_nest_reverse_locks() {
    model(|| {
        let rqs = Arc::new([Mutex::new(vec![0usize]), Mutex::new(vec![1usize])]);
        let left_rqs = Arc::clone(&rqs);
        let left = thread::spawn(move || bridge_move(&left_rqs, 0, 0, 1));
        let right_rqs = Arc::clone(&rqs);
        let right = thread::spawn(move || bridge_move(&right_rqs, 1, 1, 0));
        left.join().unwrap();
        right.join().unwrap();
        assert_eq!(&*rqs[0].lock().unwrap(), &[1]);
        assert_eq!(&*rqs[1].lock().unwrap(), &[0]);
    });
}

const PRODUCTION_SRC: u32 = 40;
const PRODUCTION_DST: u32 = 41;

fn production_rq(cpu: u32) -> Runqueue {
    Runqueue::new(cpu as u16, ProductionArc::new(Task::new(0xF000 + cpu,
        "idle", SchedClass::Idle)))
}

fn production_task(tid: u32) -> ProductionArc<Task> {
    let task = ProductionArc::new(Task::new(tid, "loom-production",
        SchedClass::Normal { weight: 1024 }));
    task.cpu.store(PRODUCTION_SRC as u16, Ordering::Release);
    let mut allowed = cpu::CpuMask::empty();
    let _ = allowed.insert(PRODUCTION_SRC as usize);
    let _ = allowed.insert(PRODUCTION_DST as usize);
    task.cpus_allowed.store(allowed, Ordering::Release);
    task
}

fn production_enqueue(rq: &Runqueue, task: &ProductionArc<Task>) {
    let mut inner = rq.inner.lock();
    assert!(inner.enqueue(ProductionArc::clone(task)));
    rq.publish_nr_running(inner.nr_running());
}

/// The executable stable-lock seam must drive the same dequeue/mutate/restore
/// transaction modeled above; source inspection cannot establish this.
#[test]
fn production_stable_change_restores_the_owning_queue() {
    let src = production_rq(PRODUCTION_SRC);
    let task = production_task(0xF100);
    production_enqueue(&src, &task);

    let StableTaskGuard::Owned(lock) = task_rq_lock_with(
        &|cpu| if cpu == PRODUCTION_SRC { Some(&src) } else { None }, &task)
        else { panic!("queued task did not return its owning runqueue") };
    let change = SchedChange::from_lock(lock, &task, 0);
    task.sched.store_effective_class(
        SchedClass::Rt { prio: 30, policy: SchedPolicy::Fifo });
    drop(change);

    let mut inner = src.inner.lock();
    let picked = inner.pick_next_task();
    assert!(ProductionArc::ptr_eq(&picked, &task));
    assert!(matches!(picked.sched_class(), SchedClass::Rt { prio: 30, .. }));
    assert!(task.on_rq.is_queued(Ordering::Acquire));
}

/// The migration seam exposes lock-boundary probes from the shipping bridge.
/// Their observed sequence proves source detach precedes destination commit.
#[test]
fn production_migration_executes_the_detached_bridge() {
    let src = production_rq(PRODUCTION_SRC);
    let dst = production_rq(PRODUCTION_DST);
    let task = production_task(0xF101);
    production_enqueue(&src, &task);
    let get = |cpu| if cpu == PRODUCTION_SRC { Some(&src) }
        else if cpu == PRODUCTION_DST { Some(&dst) } else { None };
    let mut points = Vec::new();

    let result = move_queued_with(&get, &task, Some(PRODUCTION_DST), &|_| true,
        &mut |point, cpu, _| points.push((point, cpu)));

    assert!(matches!(result, MoveResult::Moved {
        from: PRODUCTION_SRC, to: PRODUCTION_DST
    }));
    assert_eq!(points, vec![
        (MovePoint::SourceLocked, PRODUCTION_SRC),
        (MovePoint::SourceDetached, PRODUCTION_SRC),
        (MovePoint::DestinationLocked, PRODUCTION_DST),
        (MovePoint::DestinationCommitted, PRODUCTION_DST),
    ]);
    assert_eq!(src.nr_running.load(Ordering::Acquire), 0);
    assert_eq!(dst.nr_running.load(Ordering::Acquire), 1);
    assert_eq!(task.cpu.load(Ordering::Acquire), PRODUCTION_DST as u16);
    assert!(task.on_rq.is_queued(Ordering::Acquire));
}
