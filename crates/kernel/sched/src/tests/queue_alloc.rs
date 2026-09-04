use alloc::boxed::Box;
use alloc::sync::Arc;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};
use std::alloc::System;
use std::cell::Cell;

use crate::live::runqueue::{apply_update_with, Runqueue};
use crate::{SchedClass, SchedPolicy, SchedUclamp, SchedUpdate, SchedUpdateResult, Task};

std::thread_local! {
    static WATCH: Cell<bool> = const { Cell::new(false) };
}
static VIOLATIONS: AtomicUsize = AtomicUsize::new(0);

struct CheckedAllocator;

fn record() {
    WATCH.with(|watch| {
        if watch.get() { VIOLATIONS.fetch_add(1, Ordering::Relaxed); }
    });
}

// SAFETY: all pointer/layout operations are delegated unchanged to System.
unsafe impl GlobalAlloc for CheckedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record();
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record();
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static CHECKED_ALLOCATOR: CheckedAllocator = CheckedAllocator;

struct WatchGuard;

impl WatchGuard {
    fn start() -> Self {
        VIOLATIONS.store(0, Ordering::SeqCst);
        WATCH.with(|watch| watch.set(true));
        Self
    }
}

impl Drop for WatchGuard {
    fn drop(&mut self) { WATCH.with(|watch| watch.set(false)); }
}

pub(crate) fn allocations_during(body: impl FnOnce()) -> usize {
    let guard = WatchGuard::start();
    body();
    drop(guard);
    VIOLATIONS.load(Ordering::SeqCst)
}

fn update(class: SchedClass, policy: u32) -> SchedUpdate {
    SchedUpdate { class, policy,
        clamp: SchedUclamp::new(0, crate::sched_enc::UCLAMP_CAPACITY_SCALE, 0).unwrap(),
        reset_on_fork: false, nice: None, fair_slice: None,
        reload_rt_timeslice: policy == crate::sched_enc::SCHED_RR,
        clear_rt_timeout: true, deadline: None }
}

#[test]
fn scheduler_change_restore_is_allocation_free_under_rq_lock() {
    // Positive control: prove this executable's allocator detector is live.
    let control = {
        let guard = WatchGuard::start();
        let allocation = Box::new(0x5a5a_u64);
        core::hint::black_box(&allocation);
        drop(guard);
        allocation
    };
    assert!(VIOLATIONS.load(Ordering::SeqCst) > 0,
        "positive control failed to observe a heap allocation");
    drop(control);

    let rq = Runqueue::new(7, Arc::new(Task::new(9000, "idle", SchedClass::Idle)));
    let task = Arc::new(Task::new(9001, "changed", SchedClass::Normal { weight: 1024 }));
    {
        let mut inner = rq.inner.lock();
        assert!(inner.enqueue(Arc::clone(&task)));
        rq.publish_nr_running(inner.nr_running());
    }
    let getter = |cpu| if cpu == 7 { Some(&rq) } else { None };
    let to_rt = update(SchedClass::Rt { prio: 40, policy: SchedPolicy::Fifo },
        crate::sched_enc::SCHED_FIFO);
    let to_fair = update(SchedClass::Normal { weight: 1024 },
        crate::sched_enc::SCHED_NORMAL);

    let mut first = SchedUpdateResult::Stale;
    let mut second = SchedUpdateResult::Stale;
    let traffic = allocations_during(|| {
        first = apply_update_with(&getter, &task, task.sched_policy_generation(), to_rt);
        second = apply_update_with(&getter, &task, task.sched_policy_generation(), to_fair);
    });

    assert_eq!(first, SchedUpdateResult::Applied);
    assert_eq!(second, SchedUpdateResult::Applied);
    assert_eq!(traffic, 0,
        "cross-class scheduler-change restore touched the heap under rq lock");
}
