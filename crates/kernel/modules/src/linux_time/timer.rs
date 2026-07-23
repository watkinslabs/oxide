use alloc::vec::Vec;
use core::ptr::null_mut;
use sync::{Modules as ModulesLockClass, Spinlock};

use super::clock::{jiffies_to_ns, now_ns};
use super::types::*;

const HRTIMER_STATE_ENQUEUED: u8 = 1;
const HRTIMER_MODE_REL: i32 = 1;

static TIMER_IDS: Spinlock<Vec<(usize, u64)>, ModulesLockClass> = Spinlock::new(Vec::new());
static HRTIMER_IDS: Spinlock<Vec<(usize, u64)>, ModulesLockClass> = Spinlock::new(Vec::new());

pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("init_timer", init_timer as *const () as usize),
        ("setup_timer", setup_timer as *const () as usize),
        ("timer_init_key", timer_init_key as *const () as usize),
        ("add_timer", add_timer as *const () as usize),
        ("mod_timer", mod_timer as *const () as usize),
        ("timer_reduce", timer_reduce as *const () as usize),
        ("del_timer", del_timer as *const () as usize),
        ("del_timer_sync", del_timer_sync as *const () as usize),
        ("timer_delete", del_timer as *const () as usize),
        ("timer_delete_sync", del_timer_sync as *const () as usize),
        ("timer_shutdown_sync", del_timer_sync as *const () as usize),
        ("hrtimer_init", hrtimer_init as *const () as usize),
        ("hrtimer_setup", hrtimer_setup as *const () as usize),
        ("hrtimer_start", hrtimer_start as *const () as usize),
        ("hrtimer_start_range_ns", hrtimer_start_range_ns as *const () as usize),
        ("hrtimer_cancel", hrtimer_cancel as *const () as usize),
        ("hrtimer_active", hrtimer_active as *const () as usize),
        ("hrtimer_forward", hrtimer_forward as *const () as usize),
    ] { export(name, addr, false); }
}

pub(super) extern "C" fn init_timer(t: *mut LinuxTimerList) {
    timer_init_key(t, None, 0, null_mut(), null_mut());
}

pub(super) extern "C" fn setup_timer(t: *mut LinuxTimerList, f: Option<extern "C" fn(*mut LinuxTimerList)>, data: usize) {
    let _ = data;
    timer_init_key(t, f, 0, null_mut(), null_mut());
}

pub(super) extern "C" fn timer_init_key(
    t: *mut LinuxTimerList,
    f: Option<extern "C" fn(*mut LinuxTimerList)>,
    flags: u32,
    _name: *const u8,
    _key: *mut u8,
) {
    if t.is_null() { return; }
    let _ = disarm_timer(t);
    // SAFETY: non-null pointer names caller-owned timer_list storage.
    unsafe {
        (*t).entry.next = null_mut();
        (*t).entry.pprev = null_mut();
        (*t).expires = 0;
        (*t).function = f;
        (*t).flags = flags;
    }
}

pub(super) extern "C" fn add_timer(t: *mut LinuxTimerList) { if !t.is_null() { arm_timer(t); } }

pub(super) extern "C" fn mod_timer(t: *mut LinuxTimerList, expires: u64) -> i32 {
    if t.is_null() { return 0; }
    // SAFETY: non-null pointer names caller-owned timer_list storage.
    unsafe { (*t).expires = expires; }
    arm_timer(t)
}

pub(super) extern "C" fn timer_reduce(t: *mut LinuxTimerList, expires: u64) -> i32 {
    if t.is_null() { return 0; }
    // SAFETY: non-null pointer names caller-owned timer_list storage.
    let old = unsafe { (*t).expires };
    if old != 0 && old <= expires { return 0; }
    mod_timer(t, expires)
}

pub(super) extern "C" fn del_timer(t: *mut LinuxTimerList) -> i32 { disarm_timer(t) }
pub(super) extern "C" fn del_timer_sync(t: *mut LinuxTimerList) -> i32 { disarm_timer(t) }

pub(super) extern "C" fn hrtimer_init(t: *mut LinuxHrtimer, clock_id: i32, mode: i32) {
    let _ = clock_id;
    hrtimer_setup(t, None, mode);
}

pub(super) extern "C" fn hrtimer_setup(t: *mut LinuxHrtimer, f: Option<extern "C" fn(*mut LinuxHrtimer) -> i32>, mode: i32) {
    if t.is_null() { return; }
    let _ = hrtimer_cancel(t);
    // SAFETY: non-null pointer names caller-owned hrtimer storage.
    unsafe {
        (*t).node.node.parent_color = 0;
        (*t).node.node.right = null_mut();
        (*t).node.node.left = null_mut();
        (*t).node.expires = 0;
        (*t).softexpires = 0;
        (*t).function = f;
        (*t).base = null_mut();
        (*t).state = 0;
        (*t).is_rel = ((mode & HRTIMER_MODE_REL) != 0) as u8;
        (*t).is_soft = 0;
        (*t).is_hard = 0;
    }
}

pub(super) extern "C" fn hrtimer_start(t: *mut LinuxHrtimer, time: i64, mode: i32) -> i32 {
    hrtimer_start_range_ns(t, time, 0, mode);
    0
}

pub(super) extern "C" fn hrtimer_start_range_ns(t: *mut LinuxHrtimer, time: i64, delta_ns: u64, mode: i32) {
    let _ = delta_ns;
    if t.is_null() { return; }
    let base = if (mode & HRTIMER_MODE_REL) != 0 { now_ns() as i64 } else { 0 };
    let expires = base.saturating_add(time.max(0));
    let _ = hrtimer_cancel(t);
    // SAFETY: non-null pointer names caller-owned hrtimer storage.
    unsafe {
        (*t).node.expires = expires;
        (*t).softexpires = expires;
        (*t).state = HRTIMER_STATE_ENQUEUED;
        (*t).is_rel = ((mode & HRTIMER_MODE_REL) != 0) as u8;
    }
    let id = timer::register_oneshot(expires as u64, t as usize, hrtimer_fire);
    set_id(&HRTIMER_IDS, t as usize, id.raw());
}

pub(super) extern "C" fn hrtimer_cancel(t: *mut LinuxHrtimer) -> i32 {
    if t.is_null() { return 0; }
    // SAFETY: non-null pointer names caller-owned hrtimer storage.
    let was = unsafe { let was = (*t).state; (*t).state = 0; was };
    if let Some(raw) = take_id(&HRTIMER_IDS, t as usize) {
        if let Some(id) = timer::TimerId::from_raw(raw) { let _ = timer::unregister_oneshot(id); }
    }
    (was & HRTIMER_STATE_ENQUEUED != 0) as i32
}

pub(super) extern "C" fn hrtimer_active(t: *const LinuxHrtimer) -> i32 {
    if t.is_null() { return 0; }
    // SAFETY: non-null pointer names caller-owned hrtimer storage.
    unsafe { ((*t).state & HRTIMER_STATE_ENQUEUED != 0) as i32 }
}

pub(super) extern "C" fn hrtimer_forward(t: *mut LinuxHrtimer, now: i64, interval: i64) -> u64 {
    if t.is_null() || interval <= 0 { return 0; }
    // SAFETY: non-null pointer names caller-owned hrtimer storage.
    unsafe {
        let mut n = 0u64;
        while (*t).node.expires <= now {
            (*t).node.expires = (*t).node.expires.saturating_add(interval);
            (*t).softexpires = (*t).node.expires;
            n = n.saturating_add(1);
        }
        n
    }
}

fn arm_timer(t: *mut LinuxTimerList) -> i32 {
    let was = disarm_timer(t);
    // SAFETY: non-null pointer names caller-owned timer_list storage.
    let deadline = unsafe { jiffies_to_ns((*t).expires) };
    let id = timer::register_oneshot(deadline, t as usize, timer_fire);
    set_id(&TIMER_IDS, t as usize, id.raw());
    was
}

fn disarm_timer(t: *mut LinuxTimerList) -> i32 {
    if t.is_null() { return 0; }
    if let Some(raw) = take_id(&TIMER_IDS, t as usize) {
        if let Some(id) = timer::TimerId::from_raw(raw) { let _ = timer::unregister_oneshot(id); }
        return 1;
    }
    0
}

fn timer_fire(arg: usize) {
    let t = arg as *mut LinuxTimerList;
    if t.is_null() { return; }
    let _ = take_id(&TIMER_IDS, arg);
    // SAFETY: timer storage is caller-owned and valid while armed per Linux timer lifetime rules.
    unsafe { if let Some(f) = (*t).function { f(t); } }
}

fn hrtimer_fire(arg: usize) {
    let t = arg as *mut LinuxHrtimer;
    if t.is_null() { return; }
    let _ = take_id(&HRTIMER_IDS, arg);
    // SAFETY: hrtimer storage is caller-owned and valid while armed per Linux hrtimer lifetime rules.
    unsafe {
        (*t).state = 0;
        if let Some(f) = (*t).function {
            if f(t) != 0 && (*t).node.expires > now_ns() as i64 {
                (*t).state = HRTIMER_STATE_ENQUEUED;
                let id = timer::register_oneshot((*t).node.expires as u64, arg, hrtimer_fire);
                set_id(&HRTIMER_IDS, arg, id.raw());
            }
        }
    }
}

pub(super) fn set_id(tab: &Spinlock<Vec<(usize, u64)>, ModulesLockClass>, key: usize, val: u64) {
    let mut g = tab.lock();
    if let Some((_, v)) = g.iter_mut().find(|(k, _)| *k == key) { *v = val; } else { g.push((key, val)); }
}

pub(super) fn take_id(tab: &Spinlock<Vec<(usize, u64)>, ModulesLockClass>, key: usize) -> Option<u64> {
    let mut g = tab.lock();
    let idx = g.iter().position(|(k, _)| *k == key)?;
    Some(g.swap_remove(idx).1)
}

pub(super) fn delayed_work_from_timer(t: *mut LinuxTimerList) -> *mut LinuxDelayedWork {
    if t.is_null() { return null_mut(); }
    (t as usize - core::mem::size_of::<LinuxWorkStruct>()) as *mut LinuxDelayedWork
}
