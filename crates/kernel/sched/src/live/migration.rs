// Canonical queued-task CPU ownership transfer per `13§5` and `13§11`.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::{SchedClass, Task};
use super::runqueue::{RqIrq, Runqueue};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MovePoint { SourceLocked, SourceDetached, DestinationLocked, DestinationCommitted }

pub enum MoveResult {
    Moved { from: u32, to: u32 },
    Running { cpu: u32 },
    NotQueued,
    Unplaced { from: u32, task: Arc<Task> },
}

fn destination_with<'a, F, A>(get_rq: &F, task: &Task, preferred: Option<u32>,
                               tried: cpu::CpuMask, active: &A) -> Option<u32>
where F: Fn(u32) -> Option<&'a Runqueue>, A: Fn(u32) -> bool {
    let allowed = task.cpus_allowed.load(Ordering::Acquire);
    if let Some(cpu) = preferred {
        if !tried.contains(cpu as usize) && active(cpu) && get_rq(cpu).is_some()
            && allowed.contains(cpu as usize) { return Some(cpu); }
    }
    for cpu in 0..cpu::MAX_CPUS as u32 {
        if tried.contains(cpu as usize) || !allowed.contains(cpu as usize)
            || !active(cpu) || get_rq(cpu).is_none() { continue; }
        return Some(cpu);
    }
    // Relax cpuset confinement first, then force the installed active mask.
    // Configured source masks stay parked; canonical effective affinity must
    // include every fallback placement selected during CPU-down.
    let mut possible = cpu::CpuMask::empty();
    for cpu in 0..cpu::MAX_CPUS as u32 {
        if active(cpu) && get_rq(cpu).is_some() { let _ = possible.insert(cpu as usize); }
    }
    let cpuset = task.cpuset_cpus_allowed.load(Ordering::Acquire).intersect(possible);
    let relaxed = if cpuset.is_empty() { possible } else { cpuset };
    if relaxed.is_empty() { return None; }
    task.cpus_allowed.store(relaxed, Ordering::Release);
    for cpu in 0..cpu::MAX_CPUS as u32 {
        if !tried.contains(cpu as usize) && relaxed.contains(cpu as usize) { return Some(cpu); }
    }
    None
}

/// Place an already detached `Migrating` task. Every candidate is revalidated
/// while its destination rq is locked. # C: O(CPUs + log N)
#[must_use]
pub fn place_detached_with<'a, F, A, P>(get_rq: &F, task: Arc<Task>,
                                        preferred: Option<u32>, active: &A,
                                        probe: &mut P) -> Result<u32, Arc<Task>>
where F: Fn(u32) -> Option<&'a Runqueue>, A: Fn(u32) -> bool,
      P: FnMut(MovePoint, u32, &Task) {
    let mut tried = cpu::CpuMask::empty();
    loop {
        let Some(cpu) = destination_with(get_rq, &task, preferred, tried, active) else {
            return Err(task);
        };
        let _ = tried.insert(cpu as usize);
        task.cpu.store(cpu as u16, Ordering::Release);
        let Some(rq) = get_rq(cpu) else { continue; };
        let mut inner = rq.inner.lock();
        probe(MovePoint::DestinationLocked, cpu, &task);
        if !active(cpu) { continue; }
        inner.enqueue_migrated(Arc::clone(&task));
        rq.publish_nr_running(inner.nr_running());
        probe(MovePoint::DestinationCommitted, cpu, &task);
        return Ok(cpu);
    }
}

/// Move one known queued task using TaskPi -> source rq, `Migrating`, then one
/// destination rq at a time. The caller keeps one placement RCU read section
/// around this operation when `active` reads the live active mask.
/// # C: O(CPUs + log N)
#[must_use]
pub fn move_queued_with<'a, F, A, P>(get_rq: &F, task: &Arc<Task>,
                                     preferred: Option<u32>, active: &A,
                                     probe: &mut P) -> MoveResult
where F: Fn(u32) -> Option<&'a Runqueue>, A: Fn(u32) -> bool,
      P: FnMut(MovePoint, u32, &Task) {
    let pi_owner = Arc::clone(&task);
    let _pi = pi_owner.pi_lock.lock_irqsave::<RqIrq>();
    move_queued_pi_locked_with(get_rq, task, preferred, active, probe)
}

pub(crate) fn move_queued_pi_locked_with<'a, F, A, P>(get_rq: &F, task: &Arc<Task>,
    preferred: Option<u32>, active: &A, probe: &mut P) -> MoveResult
where F: Fn(u32) -> Option<&'a Runqueue>, A: Fn(u32) -> bool,
      P: FnMut(MovePoint, u32, &Task) {
    let from = task.cpu.load(Ordering::Acquire) as u32;
    let Some(src) = get_rq(from) else { return MoveResult::NotQueued; };
    let mut inner = src.inner.lock();
    if task.cpu.load(Ordering::Acquire) as u32 != from
        || task.on_rq.is_migrating(Ordering::Acquire) { return MoveResult::NotQueued; }
    let current = src.current.load(Ordering::Acquire);
    if !current.is_null() && core::ptr::eq(current.cast_const(), Arc::as_ptr(task)) {
        return MoveResult::Running { cpu: from };
    }
    if !task.on_rq.is_queued(Ordering::Acquire)
        || !task.on_class_rq.load(Ordering::Acquire) { return MoveResult::NotQueued; }
    let Some(first) = destination_with(get_rq, task, preferred, cpu::CpuMask::empty(), active)
        else { return MoveResult::NotQueued; };
    task.on_rq.begin_migration();
    probe(MovePoint::SourceLocked, from, task);
    let Some(moved) = inner.remove_task(task) else {
        task.on_rq.store(true, Ordering::Release);
        return MoveResult::NotQueued;
    };
    hal::kassert!(core::ptr::eq(Arc::as_ptr(&moved), Arc::as_ptr(task)),
        "runqueue tid resolved a different task object");
    moved.cpu.store(first as u16, Ordering::Release);
    src.publish_nr_running(inner.nr_running());
    probe(MovePoint::SourceDetached, from, &moved);
    drop(inner);
    match place_detached_with(get_rq, moved, Some(first), active, probe) {
        Ok(to) => MoveResult::Moved { from, to },
        Err(task) => MoveResult::Unplaced { from, task },
    }
}

pub(crate) fn finish_unplaced_with<'a, F, A, P>(get_rq: &F, task: Arc<Task>,
    from: u32, preferred: Option<u32>, active: &A, probe: &mut P) -> MoveResult
where F: Fn(u32) -> Option<&'a Runqueue>, A: Fn(u32) -> bool,
      P: FnMut(MovePoint, u32, &Task) {
    let pi_owner = Arc::clone(&task);
    let _pi = pi_owner.pi_lock.lock_irqsave::<RqIrq>();
    finish_unplaced_pi_locked_with(get_rq, task, from, preferred, active, probe)
}

pub(crate) fn finish_unplaced_pi_locked_with<'a, F, A, P>(get_rq: &F, mut task: Arc<Task>,
    from: u32, preferred: Option<u32>, active: &A, probe: &mut P) -> MoveResult
where F: Fn(u32) -> Option<&'a Runqueue>, A: Fn(u32) -> bool,
      P: FnMut(MovePoint, u32, &Task) {
    loop {
        match place_detached_with(get_rq, task, preferred, active, probe) {
            Ok(to) => return MoveResult::Moved { from, to },
            Err(returned) => task = returned,
        }
        sync::spin_relax::relax();
    }
}

/// Find one queued non-idle task on `cpu` without scanning other runqueues.
/// # C: O(log N)
pub fn queued_candidate(rq: &Runqueue) -> Option<Arc<Task>> {
    let inner = rq.inner.lock_irqsave::<RqIrq>();
    let task = inner.peek_next_task();
    if matches!(task.sched_class(), SchedClass::Idle) { None } else { Some(task) }
}

#[cfg(test)]
#[path = "migration/tests.rs"]
mod tests;
