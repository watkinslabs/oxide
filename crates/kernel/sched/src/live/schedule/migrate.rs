// Affinity eviction of the OUTGOING task at switch time.
//
// `schedule()` re-queues a preempted-but-still-Runnable task with
// `put_prev_task`, which stores `task.cpu = rq.cpu` and drops it into the LOCAL
// class tree without ever reading `cpus_allowed`. When the mask lost this CPU
// while the task was running (a `sched_setaffinity(2)` call, a `CPUAffinity=`
// unit, a cgroup `cpuset.cpus` write), that re-queue puts the task straight
// back on a CPU it may not use and the next pick runs it there again — so a
// CPU-bound thread never leaves the forbidden CPU until it blocks. The
// need_resched + IPI nudge the mask writer sends is undone by exactly this
// re-queue.
//
// The task cannot simply be enqueued on the destination from `schedule()`:
//   * the local rq lock is held there, and taking a second rq lock under it is
//     an AB-BA hazard against any CPU doing the reverse;
//   * the task is still `on_cpu` at that point, and a task enqueued elsewhere
//     while still executing here can be picked by the destination CPU and run
//     from a register context this CPU has not saved yet.
// So the placement is PARKED here and performed by the INCOMING task's
// `finish_task_switch`, which runs after the outgoing task's `on_cpu` is
// cleared and after the local rq lock is released — one rq lock at a time,
// nothing held, no cross-CPU aliasing. This mirrors Linux, where the running
// case is handled by a stopper that migrates the task only once it is off-CPU.
//
// Terminal fallback: when the mask names no CPU with an installed runqueue the
// task stays where it is and keeps running, rather than being stranded — the
// kernel breaks affinity before it strands a runnable task.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use crate::{SchedClass, Task};
use crate::live::runqueue::{global_for, Runqueue};

/// Bits a `cpus_allowed` word can address. A CPU id at or above this is
/// unrepresentable in the mask and therefore unconstrained by it.
pub const MASK_BITS: u32 = 64;

/// `target` value meaning "slot empty".
const NO_TARGET: u32 = u32::MAX;

/// Does `allowed` permit `cpu`? # C: O(1)
pub fn cpu_permitted(allowed: u64, cpu: u32) -> bool {
    if cpu >= MASK_BITS { return true; }
    allowed & (1u64 << cpu) != 0
}

/// Destination for a still-Runnable outgoing task that may no longer use `cpu`,
/// or `None` when it may stay. `None` also covers the terminal fallback: a mask
/// naming no CPU with an installed runqueue leaves the task running where it
/// is (affinity broken, never stranded).
/// # C: O(N_cpus)
pub fn evict_target_with<'a, F>(get_rq: &F, cpu: u32, task: &Task) -> Option<u32>
where F: Fn(u32) -> Option<&'a Runqueue> {
    if matches!(task.sched_class(), SchedClass::Idle) { return None; }
    let allowed = task.cpus_allowed.load(Ordering::Acquire);
    if cpu_permitted(allowed, cpu) { return None; }
    let target = crate::live::ttwu::select_task_rq_with(get_rq, cpu, task);
    if target == cpu || !cpu_permitted(allowed, target) { return None; }
    if get_rq(target).is_none() { return None; }
    Some(target)
}

/// [`evict_target_with`] over the live per-CPU runqueues. # C: O(N_cpus)
pub fn evict_target(cpu: u32, task: &Task) -> Option<u32> {
    // SAFETY: `global_for` is sound for any index and yields `None` for a CPU
    // that has not completed `install_global`, which the scan skips.
    evict_target_with(&|c| unsafe { global_for(c) }, cpu, task)
}

/// One parked placement per CPU. The switcher and the drainer run on the same
/// CPU and every switch drains before the next can park, so one slot suffices —
/// the same shape as the runqueue's deferred-reap slot.
struct Parked {
    /// `Arc::into_raw` of the task awaiting placement, or null.
    task: AtomicPtr<Task>,
    /// CPU to place it on; meaningful only while `task` is non-null.
    target: AtomicU32,
}

const EMPTY: Parked = Parked {
    task: AtomicPtr::new(core::ptr::null_mut()),
    target: AtomicU32::new(NO_TARGET),
};
static PARKED: [Parked; cpu::MAX_CPUS] = [EMPTY; cpu::MAX_CPUS];

/// Park `task` for placement on `target` once the switch off `cpu` completes.
/// Returns false when the slot is already occupied, so the caller re-queues
/// locally instead — a task is never dropped on the floor for a full slot.
/// # C: O(1)
pub fn park(cpu: u32, task: &Arc<Task>, target: u32) -> bool {
    let slot = match PARKED.get(cpu as usize) { Some(s) => s, None => return false };
    if !slot.task.load(Ordering::Acquire).is_null() { return false; }
    slot.target.store(target, Ordering::Release);
    slot.task.store(Arc::into_raw(Arc::clone(task)) as *mut Task, Ordering::Release);
    true
}

/// Reclaim a parked task WITHOUT placing it — the switch it was parked for did
/// not happen, so the caller owns re-queueing it. # C: O(1)
pub fn unpark(cpu: u32) -> Option<Arc<Task>> {
    let (task, _) = take(cpu)?;
    Some(task)
}

/// Reclaim the parked task and its destination. # C: O(1)
fn take(cpu: u32) -> Option<(Arc<Task>, u32)> {
    let slot = PARKED.get(cpu as usize)?;
    let raw = slot.task.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if raw.is_null() { return None; }
    let target = slot.target.swap(NO_TARGET, Ordering::AcqRel);
    // SAFETY: `raw` came from `Arc::into_raw` in `park` and is taken exactly
    // once — the swap that reads it also clears the slot.
    Some((unsafe { Arc::from_raw(raw) }, target))
}

/// Place the task the last switch off `cpu` parked, if any. Returns the CPU to
/// kick so it re-picks. Caller must hold NO runqueue lock: this takes the
/// destination runqueue's lock.
/// # C: O(log N)
pub fn place_parked_with<'a, F>(get_rq: &F, cpu: u32) -> Option<u32>
where F: Fn(u32) -> Option<&'a Runqueue> {
    let (task, target) = take(cpu)?;
    // The destination went away between the park and here: keep the task
    // runnable on this CPU rather than stranding it.
    let dest = if get_rq(target).is_some() { target } else { cpu };
    // `dest` was just confirmed installed, so this cannot fail.
    let _ = crate::live::rq_locate::enqueue_on_with(get_rq, dest, task);
    Some(dest)
}

/// [`place_parked_with`] over the live per-CPU runqueues, plus the reschedule
/// kick the destination needs to pick the task up.
/// # C: O(log N)
pub fn place_parked(cpu: u32) {
    // SAFETY: `global_for` is sound for any index; `None` for a CPU that has
    // not installed its runqueue, which routes the task back to `cpu`.
    let dest = place_parked_with(&|c| unsafe { global_for(c) }, cpu);
    if let Some(d) = dest { if d != cpu { crate::live::ttwu::resched_curr(d); } }
}
