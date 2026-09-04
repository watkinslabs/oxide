use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicUsize, Ordering};
use std::alloc::System;

use super::*;

std::thread_local! {
    static WATCH_ALLOC: Cell<bool> = const { Cell::new(false) };
    static TRACE: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

struct CheckedAllocator;

fn record_allocation() {
    WATCH_ALLOC.with(|watch| {
        if watch.get() { ALLOCATIONS.fetch_add(1, Ordering::Relaxed); }
    });
}

// SAFETY: every allocation operation is delegated unchanged to System.
unsafe impl GlobalAlloc for CheckedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: caller supplies GlobalAlloc's valid allocation layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: caller supplies GlobalAlloc's valid allocation layout.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record_allocation();
        // SAFETY: caller returns the pointer with its original layout.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation();
        // SAFETY: caller returns the pointer and layout allocated by System.
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static CHECKED_ALLOCATOR: CheckedAllocator = CheckedAllocator;

struct AllocationWatch;

impl AllocationWatch {
    fn start() -> Self {
        ALLOCATIONS.store(0, Ordering::SeqCst);
        WATCH_ALLOC.with(|watch| watch.set(true));
        Self
    }
}

impl Drop for AllocationWatch {
    fn drop(&mut self) { WATCH_ALLOC.with(|watch| watch.set(false)); }
}

fn task(tid: u32) -> sched::Task {
    sched::Task::new(tid, "lsm-dispatch", sched::SchedClass::Normal { weight: 1024 })
}

fn trace(value: u8) { TRACE.with(|trace| trace.borrow_mut().push(value)); }
fn nice_0(_: &sched::Task, _: &sched::Task, _: i32) -> Result<(), i64> { trace(0); Ok(()) }
fn nice_1(_: &sched::Task, _: &sched::Task, _: i32) -> Result<(), i64> { trace(1); Ok(()) }
fn nice_2(_: &sched::Task, _: &sched::Task, _: i32) -> Result<(), i64> { trace(2); Ok(()) }
fn sched_noop(_: &sched::Task, _: &sched::Task) -> Result<(), i64> { Ok(()) }
fn nice_noop(_: &sched::Task, _: &sched::Task, _: i32) -> Result<(), i64> { Ok(()) }

fn take_trace() -> Vec<u8> { TRACE.with(|trace| core::mem::take(&mut *trace.borrow_mut())) }

fn module(name: &'static str, id: u64) -> LsmId { LsmId { name, id } }

#[test]
fn registration_is_stable_ordered_and_module_unique() {
    let registry = Spinlock::<TaskHooks, LockClass>::new(TaskHooks::new());
    registry.lock().register_setnice(module("two", 2), 2, nice_2);
    registry.lock().register_setnice(module("zero", 0), 0, nice_0);
    registry.lock().register_setnice(module("zero", 0), 1, nice_2);
    registry.lock().register_setnice(module("one", 1), 1, nice_1);
    let caller = task(0x7fff_f100);
    let target = task(0x7fff_f101);
    setnice(&registry, &caller, &target, 4).unwrap();
    assert_eq!(take_trace(), [0, 1, 2]);
}

#[test]
fn task_dispatch_is_allocation_free_with_live_positive_control() {
    let registry = Spinlock::<TaskHooks, LockClass>::new(TaskHooks::new());
    registry.lock().register_setnice(module("nice", 10), 0, nice_noop);
    registry.lock().register_setscheduler(module("sched", 11), 0, sched_noop);
    let caller = task(0x7fff_f102);
    let target = task(0x7fff_f103);

    let control = {
        let watch = AllocationWatch::start();
        let allocation = Box::new(0x51a7_u64);
        core::hint::black_box(&allocation);
        drop(watch);
        allocation
    };
    assert!(ALLOCATIONS.load(Ordering::SeqCst) > 0,
        "positive control did not reach the checked allocator");
    drop(control);

    let watch = AllocationWatch::start();
    setnice(&registry, &caller, &target, 7).unwrap();
    setscheduler(&registry, &caller, &target).unwrap();
    drop(watch);
    assert_eq!(ALLOCATIONS.load(Ordering::SeqCst), 0,
        "scheduler authorization dispatch allocated");
}

#[test]
fn concurrent_registration_never_exposes_a_partial_order() {
    let registry = Arc::new(Spinlock::<TaskHooks, LockClass>::new(TaskHooks::new()));
    registry.lock().register_setnice(module("two", 2), 2, nice_2);
    let caller = Arc::new(task(0x7fff_f104));
    let target = Arc::new(task(0x7fff_f105));
    setnice(&registry, &caller, &target, 0).unwrap();
    assert_eq!(take_trace(), [2], "positive control must observe the old generation");

    let mut writer = registry.lock();
    let (attempted_tx, attempted_rx) = std::sync::mpsc::channel();
    let read_registry = Arc::clone(&registry);
    let read_caller = Arc::clone(&caller);
    let read_target = Arc::clone(&target);
    let reader = std::thread::spawn(move || {
        assert!(read_registry.try_lock().is_none());
        attempted_tx.send(()).unwrap();
        setnice(&read_registry, &read_caller, &read_target, 0).unwrap();
        take_trace()
    });
    attempted_rx.recv().unwrap();
    writer.register_setnice(module("one", 1), 1, nice_1);
    drop(writer);
    assert_eq!(reader.join().unwrap(), [1, 2]);

    let mut writer = registry.lock();
    let (attempted_tx, attempted_rx) = std::sync::mpsc::channel();
    let read_registry = Arc::clone(&registry);
    let read_caller = Arc::clone(&caller);
    let read_target = Arc::clone(&target);
    let reader = std::thread::spawn(move || {
        assert!(read_registry.try_lock().is_none());
        attempted_tx.send(()).unwrap();
        setnice(&read_registry, &read_caller, &read_target, 0).unwrap();
        take_trace()
    });
    attempted_rx.recv().unwrap();
    writer.register_setnice(module("zero", 0), 0, nice_0);
    drop(writer);
    assert_eq!(reader.join().unwrap(), [0, 1, 2]);
}
