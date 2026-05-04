// Hosted unit tests covering invariants 6 (RT preempts Normal) and 7
// (idle uniqueness) plus runqueue insert/pick/remove correctness.

extern crate alloc;
use super::*;
use crate::cfs::CfsRunqueue;
use crate::rt::{RtRunqueue, RT_PRIO_COUNT};
use crate::runqueue::RunqueueInner;
use crate::task::{SchedClass, SchedPolicy, Task, TaskState};

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

fn rt(tid: u32, prio: u8) -> Arc<Task> {
    Arc::new(Task::new(tid, "rt", SchedClass::Rt { prio, policy: SchedPolicy::Fifo }))
}

fn normal(tid: u32, vruntime: u64, weight: u32) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "normal", SchedClass::Normal { weight }));
    t.vruntime.store(vruntime, Ordering::Release);
    t
}

fn idle(tid: u32) -> Arc<Task> {
    Arc::new(Task::new(tid, "idle", SchedClass::Idle))
}

// ---------------------------------------------------------------------------
// RT runqueue
// ---------------------------------------------------------------------------

#[test]
fn rt_empty() {
    let q = RtRunqueue::new();
    assert!(!q.has_runnable());
    assert_eq!(q.nr_running(), 0);
}

#[test]
fn rt_pick_highest_priority_first() {
    let mut q = RtRunqueue::new();
    q.enqueue(rt(1, 10));
    q.enqueue(rt(2, 99));
    q.enqueue(rt(3, 50));
    let t = q.pick_highest().unwrap();
    assert_eq!(t.tid, 2);
    let t = q.pick_highest().unwrap();
    assert_eq!(t.tid, 3);
    let t = q.pick_highest().unwrap();
    assert_eq!(t.tid, 1);
    assert!(q.pick_highest().is_none());
}

#[test]
fn rt_fifo_within_priority() {
    let mut q = RtRunqueue::new();
    q.enqueue(rt(10, 50));
    q.enqueue(rt(11, 50));
    q.enqueue(rt(12, 50));
    assert_eq!(q.pick_highest().unwrap().tid, 10);
    assert_eq!(q.pick_highest().unwrap().tid, 11);
    assert_eq!(q.pick_highest().unwrap().tid, 12);
}

#[test]
fn rt_remove_by_tid() {
    let mut q = RtRunqueue::new();
    q.enqueue(rt(1, 30));
    q.enqueue(rt(2, 30));
    q.enqueue(rt(3, 60));
    let t = q.remove(2).unwrap();
    assert_eq!(t.tid, 2);
    assert_eq!(q.nr_running(), 2);
    assert_eq!(q.pick_highest().unwrap().tid, 3);
    assert_eq!(q.pick_highest().unwrap().tid, 1);
}

#[test]
fn rt_remove_clears_bitmap_when_bucket_empty() {
    let mut q = RtRunqueue::new();
    q.enqueue(rt(1, 50));
    q.remove(1).unwrap();
    // Bucket 50 is now empty; nothing should pick.
    assert!(!q.has_runnable());
}

#[test]
fn rt_peek_does_not_remove() {
    let mut q = RtRunqueue::new();
    q.enqueue(rt(1, 99));
    let peek_tid = q.peek_highest().unwrap().tid;
    assert_eq!(peek_tid, 1);
    assert_eq!(q.nr_running(), 1);
}

#[test]
fn rt_priority_constant_matches_spec() {
    // `13§3`: RT prio 1..=99 ⇒ slot count 100 (with 0 unused).
    assert_eq!(RT_PRIO_COUNT, 100);
}

// ---------------------------------------------------------------------------
// CFS runqueue
// ---------------------------------------------------------------------------

#[test]
fn cfs_pick_leftmost_lowest_vruntime() {
    let mut q = CfsRunqueue::new();
    q.enqueue(normal(1, 100, 1024));
    q.enqueue(normal(2,  50, 1024));
    q.enqueue(normal(3, 200, 1024));
    assert_eq!(q.pick_leftmost().unwrap().tid, 2);
    assert_eq!(q.pick_leftmost().unwrap().tid, 1);
    assert_eq!(q.pick_leftmost().unwrap().tid, 3);
    assert!(q.pick_leftmost().is_none());
}

#[test]
fn cfs_min_vruntime_tracks_leftmost() {
    let mut q = CfsRunqueue::new();
    q.enqueue(normal(1, 100, 1024));
    q.enqueue(normal(2,  50, 1024));
    assert_eq!(q.min_vruntime(), 50);
    q.pick_leftmost().unwrap();
    assert_eq!(q.min_vruntime(), 100);
    q.pick_leftmost().unwrap();
    assert_eq!(q.min_vruntime(), 0); // empty
}

#[test]
fn cfs_ties_disambiguated_by_tid() {
    let mut q = CfsRunqueue::new();
    q.enqueue(normal(7, 100, 1024));
    q.enqueue(normal(3, 100, 1024));
    q.enqueue(normal(5, 100, 1024));
    // Same vruntime ⇒ key tie broken by tid; lower tid leftmost.
    assert_eq!(q.pick_leftmost().unwrap().tid, 3);
    assert_eq!(q.pick_leftmost().unwrap().tid, 5);
    assert_eq!(q.pick_leftmost().unwrap().tid, 7);
}

#[test]
fn cfs_remove_by_tid() {
    let mut q = CfsRunqueue::new();
    q.enqueue(normal(1, 10, 1024));
    q.enqueue(normal(2, 20, 1024));
    let t = q.remove(2).unwrap();
    assert_eq!(t.tid, 2);
    assert_eq!(q.nr_running(), 1);
    assert_eq!(q.pick_leftmost().unwrap().tid, 1);
}

// ---------------------------------------------------------------------------
// Runqueue
// ---------------------------------------------------------------------------

#[test]
fn rq_idle_picked_when_empty() {
    let id = idle(0);
    let mut rq = RunqueueInner::new(0, Arc::clone(&id));
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, id.tid);
    // Re-pick still yields idle (idle uniqueness, `13§2` inv 7).
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, id.tid);
}

#[test]
fn rq_rt_preempts_normal_invariant_6() {
    let mut rq = RunqueueInner::new(0, idle(0));
    rq.enqueue(normal(10, 0, 1024));
    rq.enqueue(rt(20, 50));
    // Even though Normal was enqueued first, RT must pick first.
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, 20);
    // Then Normal.
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, 10);
}

#[test]
fn rq_idle_only_when_no_runnable_invariant_7() {
    let id = idle(0);
    let mut rq = RunqueueInner::new(0, Arc::clone(&id));
    rq.enqueue(normal(1, 5, 1024));
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, 1);
    // Now the only runnable is gone ⇒ idle picked.
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, id.tid);
}

#[test]
fn rq_enqueue_idle_panics() {
    let mut rq = RunqueueInner::new(0, idle(0));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rq.enqueue(idle(99));
    }));
    assert!(result.is_err(), "enqueueing an Idle-class task must panic");
}

#[test]
fn rq_remove_finds_in_either_class() {
    let mut rq = RunqueueInner::new(0, idle(0));
    rq.enqueue(rt(1, 20));
    rq.enqueue(normal(2, 100, 1024));
    let a = rq.remove(2).unwrap();
    assert_eq!(a.tid, 2);
    let b = rq.remove(1).unwrap();
    assert_eq!(b.tid, 1);
    assert!(rq.remove(99).is_none());
}

#[test]
fn rq_peek_does_not_drain() {
    let mut rq = RunqueueInner::new(0, idle(0));
    rq.enqueue(rt(7, 80));
    let p = rq.peek_next_task();
    assert_eq!(p.tid, 7);
    assert_eq!(rq.nr_running(), 1);
    let pick = rq.pick_next_task();
    assert_eq!(pick.tid, 7);
    assert_eq!(rq.nr_running(), 0);
}

// ---------------------------------------------------------------------------
// Task state CAS
// ---------------------------------------------------------------------------

#[test]
fn task_cas_state_transitions() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    assert_eq!(t.state(), TaskState::Runnable);
    t.cas_state(TaskState::Runnable, TaskState::Sleeping).unwrap();
    assert_eq!(t.state(), TaskState::Sleeping);
    // Wrong-from CAS fails without changing state.
    let err = t.cas_state(TaskState::Runnable, TaskState::Zombie).unwrap_err();
    assert_eq!(err, TaskState::Sleeping);
    assert_eq!(t.state(), TaskState::Sleeping);
    t.cas_state(TaskState::Sleeping, TaskState::Runnable).unwrap();
    assert_eq!(t.state(), TaskState::Runnable);
}

#[test]
fn task_lift_vruntime_respects_floor() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    t.vruntime.store(50, Ordering::Release);
    t.lift_vruntime(100);
    assert_eq!(t.vruntime.load(Ordering::Acquire), 100);
    // Lifting below current is a no-op.
    t.lift_vruntime(20);
    assert_eq!(t.vruntime.load(Ordering::Acquire), 100);
}

#[test]
fn task_kernel_stack_starts_null() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    assert!(t.kernel_stack.load(Ordering::Acquire).is_null());
}

#[test]
fn task_arch_ctx_buffer_is_zero_initialised() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    // SAFETY: hosted test; we are the sole accessor of `t.arch_ctx`.
    let buf = unsafe { &*t.arch_ctx.get() };
    assert!(buf.0.iter().all(|&b| b == 0));
    assert_eq!(buf.0.len(), crate::ARCH_CTX_SIZE);
}

#[test]
fn task_arch_ctx_ptr_round_trips() {
    // `arch_ctx_ptr::<C>()` aliases the buffer; writing through
    // it then reading via the buffer view yields the same bytes.
    #[repr(C)]
    struct FakeCtx { rsp: u64, marker: u64 }
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    // SAFETY: hosted test; we are the sole accessor of `t.arch_ctx`; FakeCtx is 16 B which fits ARCH_CTX_SIZE.
    unsafe {
        let p = t.arch_ctx_ptr::<FakeCtx>();
        (*p).rsp = 0xdead_b000_dead_b000;
        (*p).marker = 0xfeedface;
    }
    // Read back via the byte buffer.
    // SAFETY: hosted test; sole accessor; reading the same storage.
    let buf = unsafe { &*t.arch_ctx.get() };
    let rsp = u64::from_ne_bytes(buf.0[0..8].try_into().unwrap());
    let marker = u64::from_ne_bytes(buf.0[8..16].try_into().unwrap());
    assert_eq!(rsp,    0xdead_b000_dead_b000);
    assert_eq!(marker, 0xfeedface);
}

#[test]
fn task_kthread_has_no_mm() {
    // `Task::new` is the kthread constructor (per `13§5` field list,
    // kernel threads have no `mm`).
    let t = Task::new(1, "kt", SchedClass::Normal { weight: 1024 });
    // SAFETY: hosted test; single-threaded.
    assert!(unsafe { t.mm_ref() }.is_none(), "kthread Task must not carry an mm");
}

#[test]
fn task_user_carries_mm() {
    // User tasks per `13§5` carry `Arc<AddressSpace>`. The Arc is
    // shared (CLONE_VM siblings get a clone of the same Arc).
    let mm = vmm::AddressSpace::new(0).expect("AddressSpace::new should succeed");
    let t1 = Task::new_user(10, "u1", SchedClass::Normal { weight: 1024 }, alloc::sync::Arc::clone(&mm));
    let t2 = Task::new_user(11, "u2", SchedClass::Normal { weight: 1024 }, alloc::sync::Arc::clone(&mm));

    // SAFETY: hosted test; single-threaded; no concurrent writer.
    let m1 = unsafe { t1.mm_ref() }.expect("u1 mm");
    // SAFETY: same as above.
    let m2 = unsafe { t2.mm_ref() }.expect("u2 mm");
    assert!(alloc::sync::Arc::ptr_eq(m1, m2), "CLONE_VM siblings must share the same AS instance");
    // The original handle plus two task clones = 3 strong refs.
    assert_eq!(alloc::sync::Arc::strong_count(&mm), 3);
}
