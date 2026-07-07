// Linux timer/workqueue KPI exports for loadable drivers.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use sync::{Spinlock, Modules as ModulesLockClass};

pub const KPI_HZ: u64 = 100;
const NSEC_PER_USEC: u64 = 1_000;
const NSEC_PER_MSEC: u64 = 1_000_000;
const NSEC_PER_SEC: u64 = 1_000_000_000;
const USEC_PER_SEC: u64 = 1_000_000;
const MSEC_PER_SEC: u64 = 1_000;
const DEFAULT_KTHREAD_NAME: &str = "kthread";

#[repr(C)]
pub struct LinuxTimerList {
    expires: u64,
    function: Option<extern "C" fn(*mut LinuxTimerList)>,
    data: usize,
    active: u32,
    oxide_id: u64,
}
#[repr(C)]
pub struct LinuxHrtimer {
    expires_ns: i64,
    function: Option<extern "C" fn(*mut LinuxHrtimer) -> i32>,
    active: u32,
    oxide_id: u64,
}
#[repr(C)]
pub struct LinuxWorkStruct { data: AtomicUsize, func: Option<extern "C" fn(*mut LinuxWorkStruct)> }
#[repr(C)]
pub struct LinuxDelayedWork { work: LinuxWorkStruct, delay: u64, oxide_id: u64 }
#[repr(C)]
pub struct LinuxTaskStruct {
    pid: i32,
    should_stop: AtomicI32,
    result: AtomicI32,
    done: AtomicBool,
    started: AtomicBool,
    start: *mut KthreadStart,
}
#[repr(C)]
pub struct LinuxTaskletStruct { next: *mut LinuxTaskletStruct, state: u64, count: AtomicUsize, func: Option<extern "C" fn(usize)>, data: usize }

type KthreadFn = extern "C" fn(*mut u8) -> i32;
type NowHook = fn() -> u64;

#[no_mangle]
pub static jiffies: AtomicU64 = AtomicU64::new(0);
#[no_mangle]
pub static jiffies_64: AtomicU64 = AtomicU64::new(0);

static NOW_HOOK: AtomicPtr<()> = AtomicPtr::new(null_mut());
static FALLBACK_NS: AtomicU64 = AtomicU64::new(0);
static NEXT_PID: AtomicI32 = AtomicI32::new(1);
static WORK_QUEUE: Spinlock<Vec<usize>, ModulesLockClass> = Spinlock::new(Vec::new());
static WORKER_STARTED: AtomicBool = AtomicBool::new(false);
static CURRENT_KTHREAD: AtomicPtr<LinuxTaskStruct> = AtomicPtr::new(null_mut());

#[cfg(target_os = "oxide-kernel")]
static WORK_WAIT: sched::live::WaitList = sched::live::WaitList::new();

struct KthreadStart { task: *mut LinuxTaskStruct, func: KthreadFn, data: *mut u8, name: &'static str }

/// Install kernel time source used by Linux KPI time exports.
/// # C: O(1)
pub fn set_now_hook(f: NowHook) {
    NOW_HOOK.store(f as *mut (), Ordering::Release);
}

/// Register Linux timer/workqueue KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    init_runtime();
    use crate::symtab::export;
    for (name, addr) in [
        ("jiffies", &jiffies as *const AtomicU64 as usize),
        ("jiffies_64", &jiffies_64 as *const AtomicU64 as usize),
        ("msecs_to_jiffies", msecs_to_jiffies as *const () as usize),
        ("usecs_to_jiffies", usecs_to_jiffies as *const () as usize),
        ("nsecs_to_jiffies", nsecs_to_jiffies as *const () as usize),
        ("jiffies_to_msecs", jiffies_to_msecs as *const () as usize),
        ("jiffies_to_usecs", jiffies_to_usecs as *const () as usize),
        ("ktime_get", ktime_get as *const () as usize),
        ("ktime_get_ns", ktime_get_ns as *const () as usize),
        ("ktime_set", ktime_set as *const () as usize),
        ("ns_to_ktime", ns_to_ktime as *const () as usize),
        ("ktime_to_ns", ktime_to_ns as *const () as usize),
        ("ktime_add_ns", ktime_add_ns as *const () as usize),
        ("ktime_sub_ns", ktime_sub_ns as *const () as usize),
        ("msleep", msleep as *const () as usize),
        ("usleep_range", usleep_range as *const () as usize),
        ("udelay", udelay as *const () as usize),
        ("mdelay", mdelay as *const () as usize),
        ("init_timer", init_timer as *const () as usize),
        ("setup_timer", setup_timer as *const () as usize),
        ("add_timer", add_timer as *const () as usize),
        ("mod_timer", mod_timer as *const () as usize),
        ("del_timer", del_timer as *const () as usize),
        ("del_timer_sync", del_timer_sync as *const () as usize),
        ("hrtimer_init", hrtimer_init as *const () as usize),
        ("hrtimer_start", hrtimer_start as *const () as usize),
        ("hrtimer_cancel", hrtimer_cancel as *const () as usize),
        ("init_work", init_work as *const () as usize),
        ("schedule_work", schedule_work as *const () as usize),
        ("flush_scheduled_work", flush_scheduled_work as *const () as usize),
        ("cancel_work_sync", cancel_work_sync as *const () as usize),
        ("init_delayed_work", init_delayed_work as *const () as usize),
        ("schedule_delayed_work", schedule_delayed_work as *const () as usize),
        ("cancel_delayed_work_sync", cancel_delayed_work_sync as *const () as usize),
        ("kthread_create", kthread_create as *const () as usize),
        ("wake_up_process", wake_up_process as *const () as usize),
        ("kthread_should_stop", kthread_should_stop as *const () as usize),
        ("kthread_stop", kthread_stop as *const () as usize),
        ("set_current_state", set_current_state as *const () as usize),
        ("schedule", schedule as *const () as usize),
        ("tasklet_init", tasklet_init as *const () as usize),
        ("tasklet_schedule", tasklet_schedule as *const () as usize),
        ("tasklet_kill", tasklet_kill as *const () as usize),
        ("tasklet_disable", tasklet_disable as *const () as usize),
        ("tasklet_enable", tasklet_enable as *const () as usize),
    ] { export(name, addr, false); }
}

fn init_runtime() {
    if WORKER_STARTED.swap(true, Ordering::AcqRel) { return; }
    #[cfg(target_os = "oxide-kernel")]
    {
        let tid = sched::live::next_tid();
        // SAFETY: module exports initialise after the live runqueue exists; worker entry is static.
        let _ = unsafe { sched::live::spawn_kernel_thread(tid, "kworker", worker_entry, 0) };
    }
}

extern "C" fn msecs_to_jiffies(ms: u32) -> u64 { div_ceil(ms as u64 * KPI_HZ, MSEC_PER_SEC) }
extern "C" fn usecs_to_jiffies(us: u32) -> u64 { div_ceil(us as u64 * KPI_HZ, USEC_PER_SEC) }
extern "C" fn nsecs_to_jiffies(ns: u64) -> u64 { div_ceil(ns.saturating_mul(KPI_HZ), NSEC_PER_SEC) }
extern "C" fn jiffies_to_msecs(j: u64) -> u32 { ((j.saturating_mul(MSEC_PER_SEC)) / KPI_HZ) as u32 }
extern "C" fn jiffies_to_usecs(j: u64) -> u32 { ((j.saturating_mul(USEC_PER_SEC)) / KPI_HZ) as u32 }
extern "C" fn ktime_get() -> i64 { ktime_get_ns() }
extern "C" fn ktime_get_ns() -> i64 { now_ns() as i64 }
extern "C" fn ktime_set(secs: i64, nsecs: u64) -> i64 { secs.saturating_mul(NSEC_PER_SEC as i64).saturating_add(nsecs as i64) }
extern "C" fn ns_to_ktime(ns: i64) -> i64 { ns }
extern "C" fn ktime_to_ns(kt: i64) -> i64 { kt }
extern "C" fn ktime_add_ns(kt: i64, ns: u64) -> i64 { kt.saturating_add(ns as i64) }
extern "C" fn ktime_sub_ns(kt: i64, ns: u64) -> i64 { kt.saturating_sub(ns as i64) }

extern "C" fn msleep(ms: u32) { sleep_ns(ms as u64 * NSEC_PER_MSEC); }
extern "C" fn usleep_range(min: u32, max: u32) { let _ = max; sleep_ns(min as u64 * NSEC_PER_USEC); }
extern "C" fn udelay(us: u32) { busy_delay_ns(us as u64 * NSEC_PER_USEC); }
extern "C" fn mdelay(ms: u32) { busy_delay_ns(ms as u64 * NSEC_PER_MSEC); }

extern "C" fn init_timer(t: *mut LinuxTimerList) {
    if t.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned timer_list storage.
    unsafe { (*t).expires = 0; (*t).function = None; (*t).data = 0; (*t).active = 0; (*t).oxide_id = 0; }
}
extern "C" fn setup_timer(t: *mut LinuxTimerList, f: Option<extern "C" fn(*mut LinuxTimerList)>, data: usize) {
    if t.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned timer_list storage.
    unsafe { (*t).expires = 0; (*t).function = f; (*t).data = data; (*t).active = 0; (*t).oxide_id = 0; }
}
extern "C" fn add_timer(t: *mut LinuxTimerList) { if !t.is_null() { arm_timer(t); } }
extern "C" fn mod_timer(t: *mut LinuxTimerList, expires: u64) -> i32 {
    if t.is_null() { return 0; }
    // SAFETY: non-null pointer names caller-owned timer_list storage.
    unsafe { (*t).expires = expires; }
    arm_timer(t)
}
extern "C" fn del_timer(t: *mut LinuxTimerList) -> i32 { disarm_timer(t) }
extern "C" fn del_timer_sync(t: *mut LinuxTimerList) -> i32 { disarm_timer(t) }

extern "C" fn hrtimer_init(t: *mut LinuxHrtimer, clock_id: i32, mode: i32) {
    let _ = (clock_id, mode);
    if t.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned hrtimer storage.
    unsafe { (*t).expires_ns = 0; (*t).function = None; (*t).active = 0; (*t).oxide_id = 0; }
}
extern "C" fn hrtimer_start(t: *mut LinuxHrtimer, time: i64, mode: i32) -> i32 {
    let _ = mode;
    if t.is_null() { return 0; }
    // SAFETY: non-null pointer names caller-owned hrtimer storage.
    unsafe { (*t).expires_ns = time; (*t).active = 1; }
    let deadline = if time <= 0 { now_ns() } else { time as u64 };
    let id = timer::register_oneshot(deadline, t as usize, hrtimer_fire);
    // SAFETY: non-null pointer names caller-owned hrtimer storage.
    unsafe { (*t).oxide_id = id.raw(); }
    0
}
extern "C" fn hrtimer_cancel(t: *mut LinuxHrtimer) -> i32 {
    if t.is_null() { return 0; }
    // SAFETY: non-null pointer names caller-owned hrtimer storage.
    let raw = unsafe { let raw = (*t).oxide_id; (*t).oxide_id = 0; (*t).active = 0; raw };
    timer::TimerId::from_raw(raw).is_some_and(timer::unregister_oneshot) as i32
}

extern "C" fn init_work(w: *mut LinuxWorkStruct, f: Option<extern "C" fn(*mut LinuxWorkStruct)>) {
    if w.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned work_struct storage.
    unsafe { (*w).data.store(0, Ordering::Release); (*w).func = f; }
}
extern "C" fn schedule_work(w: *mut LinuxWorkStruct) -> i32 {
    if w.is_null() { return 0; }
    enqueue_work(w);
    1
}
extern "C" fn flush_scheduled_work() { drain_work_once(); }
extern "C" fn cancel_work_sync(w: *mut LinuxWorkStruct) -> i32 {
    if w.is_null() { return 0; }
    let mut g = WORK_QUEUE.lock();
    let before = g.len();
    g.retain(|p| *p != w as usize);
    // SAFETY: non-null pointer names caller-owned work_struct storage.
    unsafe { (*w).data.store(0, Ordering::Release); }
    (g.len() != before) as i32
}
extern "C" fn init_delayed_work(dw: *mut LinuxDelayedWork, f: Option<extern "C" fn(*mut LinuxWorkStruct)>) {
    if dw.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned delayed_work storage.
    unsafe { init_work(&mut (*dw).work, f); (*dw).delay = 0; (*dw).oxide_id = 0; }
}
extern "C" fn schedule_delayed_work(dw: *mut LinuxDelayedWork, delay: u64) -> i32 {
    if dw.is_null() { return 0; }
    // SAFETY: non-null pointer names caller-owned delayed_work storage.
    unsafe { (*dw).delay = delay; }
    let deadline = now_ns().saturating_add(jiffies_to_ns(delay));
    let id = timer::register_oneshot(deadline, dw as usize, delayed_work_fire);
    // SAFETY: non-null pointer names caller-owned delayed_work storage.
    unsafe { (*dw).oxide_id = id.raw(); }
    1
}
extern "C" fn cancel_delayed_work_sync(dw: *mut LinuxDelayedWork) -> i32 {
    if dw.is_null() { return 0; }
    // SAFETY: non-null pointer names caller-owned delayed_work storage.
    let raw = unsafe { let raw = (*dw).oxide_id; (*dw).oxide_id = 0; raw };
    let stopped = timer::TimerId::from_raw(raw).is_some_and(timer::unregister_oneshot);
    // SAFETY: non-null pointer names caller-owned delayed_work storage.
    let queued = unsafe { cancel_work_sync(&mut (*dw).work) != 0 };
    (stopped || queued) as i32
}

extern "C" fn kthread_create(threadfn: Option<KthreadFn>, data: *mut u8, namefmt: *const u8) -> *mut LinuxTaskStruct {
    let Some(func) = threadfn else { return null_mut(); };
    let pid = NEXT_PID.fetch_add(1, Ordering::AcqRel);
    let name = leak_name(namefmt);
    let task = Box::new(LinuxTaskStruct {
        pid,
        should_stop: AtomicI32::new(0),
        result: AtomicI32::new(0),
        done: AtomicBool::new(false),
        started: AtomicBool::new(false),
        start: null_mut(),
    });
    let task = Box::into_raw(task);
    let start = Box::into_raw(Box::new(KthreadStart { task, func, data, name }));
    // SAFETY: task points to the allocation just created above.
    unsafe { (*task).start = start; }
    task
}
extern "C" fn wake_up_process(task: *mut LinuxTaskStruct) -> i32 {
    if task.is_null() { return 0; }
    // SAFETY: non-null task pointer was allocated by kthread_create.
    let start = unsafe {
        if (*task).started.swap(true, Ordering::AcqRel) { return 0; }
        (*task).start
    };
    if start.is_null() { return 0; }
    #[cfg(target_os = "oxide-kernel")]
    {
        let tid = sched::live::next_tid();
        // SAFETY: runqueue is live; start points to a KthreadStart owned by task.
        if unsafe { sched::live::spawn_kernel_thread(tid, (*start).name, kthread_entry, start as usize) }.is_err() { return 0; }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    kthread_entry_hosted(start);
    1
}
extern "C" fn kthread_should_stop() -> i32 {
    let task = CURRENT_KTHREAD.load(Ordering::Acquire);
    if task.is_null() { return 0; }
    // SAFETY: current kthread pointer is set only while the backing task lives.
    unsafe { (*task).should_stop.load(Ordering::Acquire) }
}
extern "C" fn kthread_stop(task: *mut LinuxTaskStruct) -> i32 {
    if task.is_null() { return 0; }
    // SAFETY: non-null task pointer was allocated by kthread_create.
    unsafe { (*task).should_stop.store(1, Ordering::Release); }
    while unsafe { !(*task).done.load(Ordering::Acquire) } {
        schedule();
    }
    // SAFETY: task is stopped and no longer referenced by the trampoline.
    unsafe {
        let result = (*task).result.load(Ordering::Acquire);
        drop(Box::from_raw((*task).start));
        drop(Box::from_raw(task));
        result
    }
}
extern "C" fn set_current_state(state: i32) { let _ = state; }
extern "C" fn schedule() {
    #[cfg(target_os = "oxide-kernel")]
    unsafe {
        // SAFETY: caller requested a Linux schedule point in process/kthread context.
        sched::live::schedule();
    }
}

extern "C" fn tasklet_init(t: *mut LinuxTaskletStruct, f: Option<extern "C" fn(usize)>, data: usize) {
    if t.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned tasklet_struct storage.
    unsafe { (*t).next = null_mut(); (*t).state = 0; (*t).count.store(0, Ordering::Release); (*t).func = f; (*t).data = data; }
}
extern "C" fn tasklet_schedule(t: *mut LinuxTaskletStruct) {
    if t.is_null() { return; }
    let deadline = now_ns();
    let _ = timer::register_oneshot(deadline, t as usize, tasklet_fire);
}
extern "C" fn tasklet_kill(t: *mut LinuxTaskletStruct) { if !t.is_null() { unsafe { (*t).state = 0; } } }
extern "C" fn tasklet_disable(t: *mut LinuxTaskletStruct) { if !t.is_null() { unsafe { (*t).count.fetch_add(1, Ordering::AcqRel); } } }
extern "C" fn tasklet_enable(t: *mut LinuxTaskletStruct) { if !t.is_null() { unsafe { (*t).count.fetch_sub(1, Ordering::AcqRel); } } }

#[cfg(target_os = "oxide-kernel")]
extern "C" fn worker_entry(_arg: usize) -> ! {
    loop {
        while drain_work_once() {}
        // SAFETY: kworker has no locks held and immediately yields after parking.
        unsafe { WORK_WAIT.park(); sched::live::schedule(); }
    }
}

#[cfg(target_os = "oxide-kernel")]
extern "C" fn kthread_entry(arg: usize) -> ! {
    let start = arg as *mut KthreadStart;
    run_kthread(start);
    if let Some(cur) = sched::live::current() { sched::live::mark_done(cur); }
    unsafe {
        // SAFETY: kthread is exiting from its own process context.
        sched::live::schedule();
    }
    loop { core::hint::spin_loop(); }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn kthread_entry_hosted(start: *mut KthreadStart) {
    if !start.is_null() {
        // SAFETY: hosted kthread start pointer is allocated by kthread_create.
        let _ = unsafe { (*start).name };
    }
    run_kthread(start);
}

fn run_kthread(start: *mut KthreadStart) {
    if start.is_null() { return; }
    // SAFETY: start is allocated by kthread_create and remains owned by task until stop.
    let task = unsafe { (*start).task };
    CURRENT_KTHREAD.store(task, Ordering::Release);
    // SAFETY: start fields are immutable after kthread_create.
    let result = unsafe { ((*start).func)((*start).data) };
    // SAFETY: task pointer is valid until kthread_stop observes done.
    unsafe {
        (*task).result.store(result, Ordering::Release);
        (*task).done.store(true, Ordering::Release);
    }
    CURRENT_KTHREAD.store(null_mut(), Ordering::Release);
}

fn arm_timer(t: *mut LinuxTimerList) -> i32 {
    let was = disarm_timer(t);
    // SAFETY: non-null pointer names caller-owned timer_list storage.
    let deadline = unsafe { jiffies_to_ns((*t).expires) };
    let id = timer::register_oneshot(deadline, t as usize, timer_fire);
    // SAFETY: non-null pointer names caller-owned timer_list storage.
    unsafe { (*t).active = 1; (*t).oxide_id = id.raw(); }
    was
}
fn disarm_timer(t: *mut LinuxTimerList) -> i32 {
    if t.is_null() { return 0; }
    // SAFETY: non-null pointer names caller-owned timer_list storage.
    let raw = unsafe { let raw = (*t).oxide_id; (*t).oxide_id = 0; let was = (*t).active; (*t).active = 0; (raw, was) };
    if let Some(id) = timer::TimerId::from_raw(raw.0) { let _ = timer::unregister_oneshot(id); }
    raw.1 as i32
}
fn timer_fire(arg: usize) {
    let t = arg as *mut LinuxTimerList;
    if t.is_null() { return; }
    // SAFETY: timer storage is caller-owned and valid while armed per Linux timer lifetime rules.
    unsafe { (*t).active = 0; (*t).oxide_id = 0; if let Some(f) = (*t).function { f(t); } }
}
fn hrtimer_fire(arg: usize) {
    let t = arg as *mut LinuxHrtimer;
    if t.is_null() { return; }
    // SAFETY: hrtimer storage is caller-owned and valid while armed per Linux hrtimer lifetime rules.
    unsafe { (*t).active = 0; (*t).oxide_id = 0; if let Some(f) = (*t).function { f(t); } }
}
fn delayed_work_fire(arg: usize) {
    let dw = arg as *mut LinuxDelayedWork;
    if dw.is_null() { return; }
    // SAFETY: delayed_work storage is caller-owned and valid while armed.
    unsafe { (*dw).oxide_id = 0; enqueue_work(&mut (*dw).work); }
}
fn tasklet_fire(arg: usize) {
    let t = arg as *mut LinuxTaskletStruct;
    if t.is_null() { return; }
    // SAFETY: tasklet storage is caller-owned and valid while scheduled.
    unsafe { if (*t).count.load(Ordering::Acquire) == 0 { if let Some(f) = (*t).func { f((*t).data); } } }
}

fn enqueue_work(w: *mut LinuxWorkStruct) {
    // SAFETY: non-null pointer names caller-owned work_struct storage.
    if unsafe { (*w).data.swap(1, Ordering::AcqRel) } != 0 { return; }
    WORK_QUEUE.lock().push(w as usize);
    #[cfg(target_os = "oxide-kernel")]
    WORK_WAIT.wake_one();
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = drain_work_once(); }
}
fn drain_work_once() -> bool {
    let w = WORK_QUEUE.lock().pop();
    let Some(raw) = w else { return false; };
    let w = raw as *mut LinuxWorkStruct;
    // SAFETY: queued work pointer came from schedule_work and remains caller-owned until cancelled/flushed.
    unsafe { if let Some(f) = (*w).func { f(w); } (*w).data.store(0, Ordering::Release); }
    true
}

fn sleep_ns(ns: u64) {
    if ns == 0 { return; }
    #[cfg(target_os = "oxide-kernel")]
    {
        let wait = sched::live::WaitList::new();
        let deadline = now_ns().saturating_add(ns);
        let _ = timer::register_oneshot(deadline, &wait as *const _ as usize, wake_sleep);
        // SAFETY: stack wait list remains alive until this task is woken and schedule returns.
        unsafe { wait.park(); sched::live::schedule(); }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
        FALLBACK_NS.fetch_add(ns, Ordering::AcqRel);
        publish_jiffies();
    }
}
#[cfg(target_os = "oxide-kernel")]
fn wake_sleep(arg: usize) {
    let wait = arg as *const sched::live::WaitList;
    if wait.is_null() { return; }
    // SAFETY: sleep_ns keeps the stack wait list alive until this callback wakes it.
    unsafe { (*wait).wake_all(); }
}
fn busy_delay_ns(ns: u64) {
    let end = now_ns().saturating_add(ns);
    while now_ns() < end { core::hint::spin_loop(); }
}
fn now_ns() -> u64 {
    let p = NOW_HOOK.load(Ordering::Acquire);
    let ns = if p.is_null() {
        FALLBACK_NS.load(Ordering::Acquire)
    } else {
        // SAFETY: hook installed by set_now_hook with matching fn() -> u64 ABI.
        let f: NowHook = unsafe { core::mem::transmute(p) };
        f()
    };
    publish_jiffies_from(ns);
    ns
}
#[cfg(not(target_os = "oxide-kernel"))]
fn publish_jiffies() { publish_jiffies_from(FALLBACK_NS.load(Ordering::Acquire)); }
fn publish_jiffies_from(ns: u64) {
    let j = nsecs_to_jiffies(ns);
    jiffies.store(j, Ordering::Release);
    jiffies_64.store(j, Ordering::Release);
}
fn jiffies_to_ns(j: u64) -> u64 { j.saturating_mul(NSEC_PER_SEC / KPI_HZ) }
fn div_ceil(n: u64, d: u64) -> u64 { if n == 0 { 0 } else { ((n - 1) / d) + 1 } }

fn leak_name(namefmt: *const u8) -> &'static str {
    if namefmt.is_null() { return DEFAULT_KTHREAD_NAME; }
    let mut out = String::new();
    let mut i = 0usize;
    loop {
        // SAFETY: Linux caller passes a NUL-terminated format string.
        let b = unsafe { *namefmt.add(i) };
        if b == 0 { break; }
        if b == b'%' { break; }
        out.push(b as char);
        i += 1;
    }
    if out.is_empty() { DEFAULT_KTHREAD_NAME } else { Box::leak(out.into_boxed_str()) }
}

#[cfg(test)]
mod linux_time_tests;
