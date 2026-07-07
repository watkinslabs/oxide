extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};

use sync::{Modules as ModulesLockClass, Spinlock};

use super::clock::jiffies_to_ns;
use super::timer::{del_timer_sync, delayed_work_from_timer, mod_timer, timer_init_key};
use super::types::*;

const WORK_QUEUED: usize = 1;
const WORK_DISABLED: usize = 1 << 1;

static WORK_QUEUE: Spinlock<Vec<usize>, ModulesLockClass> = Spinlock::new(Vec::new());
static WORKER_STARTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "oxide-kernel")]
static WORK_WAIT: sched::live::WaitList = sched::live::WaitList::new();

pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("alloc_workqueue", alloc_workqueue as *const () as usize),
        ("destroy_workqueue", destroy_workqueue as *const () as usize),
        ("__flush_workqueue", flush_workqueue as *const () as usize),
        ("init_work", init_work as *const () as usize),
        ("schedule_work", schedule_work as *const () as usize),
        ("queue_work_on", queue_work_on as *const () as usize),
        ("flush_scheduled_work", flush_scheduled_work as *const () as usize),
        ("flush_work", flush_work as *const () as usize),
        ("cancel_work_sync", cancel_work_sync as *const () as usize),
        ("disable_work", disable_work as *const () as usize),
        ("disable_work_sync", disable_work_sync as *const () as usize),
        ("enable_work", enable_work as *const () as usize),
        ("init_delayed_work", init_delayed_work as *const () as usize),
        ("schedule_delayed_work", schedule_delayed_work as *const () as usize),
        ("queue_delayed_work_on", queue_delayed_work_on as *const () as usize),
        ("mod_delayed_work_on", mod_delayed_work_on as *const () as usize),
        ("cancel_delayed_work", cancel_delayed_work as *const () as usize),
        ("cancel_delayed_work_sync", cancel_delayed_work_sync as *const () as usize),
        ("delayed_work_timer_fn", delayed_work_timer_fn as *const () as usize),
        ("kblockd_schedule_work", kblockd_schedule_work as *const () as usize),
        ("async_schedule_node_domain", async_schedule_node_domain as *const () as usize),
    ] { export(name, addr, false); }
}

pub(super) fn init_runtime() {
    if WORKER_STARTED.swap(true, Ordering::AcqRel) { return; }
    #[cfg(target_os = "oxide-kernel")]
    {
        let tid = sched::live::next_tid();
        // SAFETY: module exports initialise after the live runqueue exists; worker entry is static.
        let _ = unsafe { sched::live::spawn_kernel_thread(tid, "kworker", worker_entry, 0) };
    }
}

pub(super) extern "C" fn alloc_workqueue(name: *const u8, flags: u32, max_active: i32) -> *mut LinuxWorkqueueStruct {
    let mut wq = Box::new(LinuxWorkqueueStruct { flags, max_active, destroyed: AtomicBool::new(false), name: [0; 32] });
    copy_name(name, &mut wq.name);
    Box::into_raw(wq)
}

pub(super) extern "C" fn destroy_workqueue(wq: *mut LinuxWorkqueueStruct) {
    if wq.is_null() { return; }
    flush_workqueue(wq);
    // SAFETY: alloc_workqueue returns this allocation and destroy_workqueue is the matching release.
    unsafe { (*wq).destroyed.store(true, Ordering::Release); drop(Box::from_raw(wq)); }
}

pub(super) extern "C" fn flush_workqueue(_wq: *mut LinuxWorkqueueStruct) {
    while drain_work_once() {}
}

pub(super) extern "C" fn init_work(w: *mut LinuxWorkStruct, f: Option<extern "C" fn(*mut LinuxWorkStruct)>) {
    if w.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned work_struct storage.
    unsafe {
        (*w).data.store(0, Ordering::Release);
        (*w).entry.next = null_mut();
        (*w).entry.prev = null_mut();
        (*w).func = f;
    }
}

pub(super) extern "C" fn schedule_work(w: *mut LinuxWorkStruct) -> i32 {
    queue_work_on(-1, null_mut(), w)
}

pub(super) extern "C" fn queue_work_on(_cpu: i32, wq: *mut LinuxWorkqueueStruct, w: *mut LinuxWorkStruct) -> i32 {
    if w.is_null() || wq_destroyed(wq) { return 0; }
    enqueue_work(w) as i32
}

pub(super) extern "C" fn flush_scheduled_work() { flush_workqueue(null_mut()); }

pub(super) extern "C" fn flush_work(w: *mut LinuxWorkStruct) -> i32 {
    if w.is_null() { return 0; }
    let mut ran = 0;
    while work_queued(w) {
        ran |= drain_work_once() as i32;
    }
    ran
}

pub(super) extern "C" fn cancel_work_sync(w: *mut LinuxWorkStruct) -> i32 {
    if w.is_null() { return 0; }
    let mut g = WORK_QUEUE.lock();
    let before = g.len();
    g.retain(|p| *p != w as usize);
    // SAFETY: non-null pointer names caller-owned work_struct storage.
    unsafe { (*w).data.fetch_and(!WORK_QUEUED, Ordering::AcqRel); }
    (g.len() != before) as i32
}

pub(super) extern "C" fn disable_work(w: *mut LinuxWorkStruct) -> i32 {
    if w.is_null() { return 0; }
    // SAFETY: non-null pointer names caller-owned work_struct storage.
    unsafe { (*w).data.fetch_or(WORK_DISABLED, Ordering::AcqRel); }
    0
}

pub(super) extern "C" fn disable_work_sync(w: *mut LinuxWorkStruct) -> i32 {
    let queued = cancel_work_sync(w);
    let _ = disable_work(w);
    queued
}

pub(super) extern "C" fn enable_work(w: *mut LinuxWorkStruct) {
    if w.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned work_struct storage.
    unsafe { (*w).data.fetch_and(!WORK_DISABLED, Ordering::AcqRel); }
}

pub(super) extern "C" fn init_delayed_work(dw: *mut LinuxDelayedWork, f: Option<extern "C" fn(*mut LinuxWorkStruct)>) {
    if dw.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned delayed_work storage.
    unsafe {
        init_work(&mut (*dw).work, f);
        timer_init_key(&mut (*dw).timer, Some(delayed_work_timer_fn), 0, null_mut(), null_mut());
        (*dw).wq = null_mut();
        (*dw).cpu = -1;
    }
}

pub(super) extern "C" fn schedule_delayed_work(dw: *mut LinuxDelayedWork, delay: u64) -> i32 {
    queue_delayed_work_on(-1, null_mut(), dw, delay)
}

pub(super) extern "C" fn queue_delayed_work_on(cpu: i32, wq: *mut LinuxWorkqueueStruct, dw: *mut LinuxDelayedWork, delay: u64) -> i32 {
    if dw.is_null() || wq_destroyed(wq) { return 0; }
    // SAFETY: non-null pointer names caller-owned delayed_work storage.
    unsafe { (*dw).wq = wq; (*dw).cpu = cpu; }
    if delay == 0 {
        // SAFETY: non-null pointer names caller-owned delayed_work storage.
        return unsafe { enqueue_work(&mut (*dw).work) as i32 };
    }
    let expires = super::clock::nsecs_to_jiffies(super::clock::now_ns().saturating_add(jiffies_to_ns(delay)));
    // SAFETY: non-null pointer names caller-owned delayed_work storage.
    unsafe { mod_timer(&mut (*dw).timer, expires) }
}

pub(super) extern "C" fn mod_delayed_work_on(cpu: i32, wq: *mut LinuxWorkqueueStruct, dw: *mut LinuxDelayedWork, delay: u64) -> i32 {
    let _ = cancel_delayed_work(dw);
    queue_delayed_work_on(cpu, wq, dw, delay)
}

pub(super) extern "C" fn cancel_delayed_work(dw: *mut LinuxDelayedWork) -> i32 {
    if dw.is_null() { return 0; }
    // SAFETY: non-null pointer names caller-owned delayed_work storage.
    unsafe { del_timer_sync(&mut (*dw).timer) }
}

pub(super) extern "C" fn cancel_delayed_work_sync(dw: *mut LinuxDelayedWork) -> i32 {
    if dw.is_null() { return 0; }
    // SAFETY: non-null pointer names caller-owned delayed_work storage.
    let stopped = unsafe { del_timer_sync(&mut (*dw).timer) != 0 };
    // SAFETY: non-null pointer names caller-owned delayed_work storage.
    let queued = unsafe { cancel_work_sync(&mut (*dw).work) != 0 };
    (stopped || queued) as i32
}

pub(super) extern "C" fn delayed_work_timer_fn(t: *mut LinuxTimerList) {
    let dw = delayed_work_from_timer(t);
    if dw.is_null() { return; }
    // SAFETY: delayed_work storage owns this timer as its embedded field.
    unsafe { let _ = queue_work_on((*dw).cpu, (*dw).wq, &mut (*dw).work); }
}

pub(super) extern "C" fn kblockd_schedule_work(w: *mut LinuxWorkStruct) -> i32 { schedule_work(w) }

pub(super) extern "C" fn async_schedule_node_domain(
    func: Option<extern "C" fn(*mut u8, usize)>,
    data: *mut u8,
    node: i32,
    domain: *mut u8,
) -> *mut u8 {
    let _ = (node, domain);
    if let Some(f) = func { f(data, 0); }
    data
}

#[cfg(target_os = "oxide-kernel")]
extern "C" fn worker_entry(_arg: usize) -> ! {
    loop {
        while drain_work_once() {}
        // SAFETY: kworker has no locks held and immediately yields after parking.
        unsafe { WORK_WAIT.park(); sched::live::schedule(); }
    }
}

fn enqueue_work(w: *mut LinuxWorkStruct) -> bool {
    // SAFETY: non-null pointer names caller-owned work_struct storage.
    let old = unsafe { (*w).data.fetch_or(WORK_QUEUED, Ordering::AcqRel) };
    if old & (WORK_QUEUED | WORK_DISABLED) != 0 { return false; }
    WORK_QUEUE.lock().push(w as usize);
    #[cfg(target_os = "oxide-kernel")]
    WORK_WAIT.wake_one();
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = drain_work_once(); }
    true
}

fn drain_work_once() -> bool {
    let w = WORK_QUEUE.lock().pop();
    let Some(raw) = w else { return false; };
    let w = raw as *mut LinuxWorkStruct;
    // SAFETY: queued work pointer came from queue_work and remains caller-owned until cancelled/flushed.
    unsafe {
        if (*w).data.load(Ordering::Acquire) & WORK_DISABLED == 0 {
            if let Some(f) = (*w).func { f(w); }
        }
        (*w).data.fetch_and(!WORK_QUEUED, Ordering::AcqRel);
    }
    true
}

fn work_queued(w: *mut LinuxWorkStruct) -> bool {
    // SAFETY: non-null pointer names caller-owned work_struct storage.
    unsafe { (*w).data.load(Ordering::Acquire) & WORK_QUEUED != 0 }
}

fn wq_destroyed(wq: *mut LinuxWorkqueueStruct) -> bool {
    if wq.is_null() { return false; }
    // SAFETY: non-null workqueue pointer came from alloc_workqueue.
    unsafe { (*wq).destroyed.load(Ordering::Acquire) }
}

fn copy_name(src: *const u8, dst: &mut [u8; 32]) {
    if src.is_null() { return; }
    for i in 0..dst.len() - 1 {
        // SAFETY: Linux caller passes a NUL-terminated format/name string.
        let b = unsafe { *src.add(i) };
        if b == 0 || b == b'%' { break; }
        dst[i] = b;
    }
}
