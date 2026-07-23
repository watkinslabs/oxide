use alloc::vec::Vec;
use core::ptr::null_mut;
use core::sync::atomic::Ordering;
use sync::{Modules as ModulesLockClass, Spinlock};

use super::clock::now_ns;
use super::timer::{set_id, take_id};
use super::types::*;

/// `tasklet_struct* → pending one-shot TimerId`, so `tasklet_kill` can cancel a
/// scheduled-but-not-yet-fired tasklet (Linux `tasklet_kill` waits out / clears
/// the pending run). Without this the one-shot outlives a killed+freed tasklet
/// and `tasklet_fire` dereferences freed storage (a B1345-class stale fire).
static TASKLET_IDS: Spinlock<Vec<(usize, u64)>, ModulesLockClass> = Spinlock::new(Vec::new());

pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("tasklet_init", tasklet_init as *const () as usize),
        ("tasklet_schedule", tasklet_schedule as *const () as usize),
        ("tasklet_kill", tasklet_kill as *const () as usize),
        ("tasklet_disable", tasklet_disable as *const () as usize),
        ("tasklet_enable", tasklet_enable as *const () as usize),
    ] { export(name, addr, false); }
}

pub(super) extern "C" fn tasklet_init(t: *mut LinuxTaskletStruct, f: Option<extern "C" fn(usize)>, data: usize) {
    if t.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned tasklet_struct storage.
    unsafe {
        (*t).next = null_mut();
        (*t).state = 0;
        (*t).count.store(0, Ordering::Release);
        (*t).func = f;
        (*t).data = data;
    }
}

pub(super) extern "C" fn tasklet_schedule(t: *mut LinuxTaskletStruct) {
    if t.is_null() { return; }
    let deadline = now_ns();
    let id = timer::register_oneshot(deadline, t as usize, tasklet_fire);
    // Record the pending one-shot so tasklet_kill can cancel it before the
    // driver frees the tasklet (else the fire dereferences freed storage).
    set_id(&TASKLET_IDS, t as usize, id.raw());
}

pub(super) extern "C" fn tasklet_kill(t: *mut LinuxTaskletStruct) {
    if !t.is_null() {
        // SAFETY: non-null pointer names caller-owned tasklet_struct storage.
        unsafe { (*t).state = 0; }
    }
    // Cancel any pending one-shot so it can't fire on the (about-to-be-freed)
    // tasklet — mirrors hrtimer_cancel/del_timer. Fires even for a null `t` to
    // stay balanced against a schedule that raced.
    if let Some(raw) = take_id(&TASKLET_IDS, t as usize) {
        if let Some(id) = timer::TimerId::from_raw(raw) { let _ = timer::unregister_oneshot(id); }
    }
}

pub(super) extern "C" fn tasklet_disable(t: *mut LinuxTaskletStruct) {
    if !t.is_null() {
        // SAFETY: non-null pointer names caller-owned tasklet_struct storage.
        unsafe { (*t).count.fetch_add(1, Ordering::AcqRel); }
    }
}

pub(super) extern "C" fn tasklet_enable(t: *mut LinuxTaskletStruct) {
    if !t.is_null() {
        // SAFETY: non-null pointer names caller-owned tasklet_struct storage.
        unsafe { (*t).count.fetch_sub(1, Ordering::AcqRel); }
    }
}

fn tasklet_fire(arg: usize) {
    // The one-shot is consumed by this fire; drop its cancel token so the table
    // doesn't leak and a later tasklet_kill on a reused pointer is a clean no-op.
    let _ = take_id(&TASKLET_IDS, arg);
    let t = arg as *mut LinuxTaskletStruct;
    if t.is_null() { return; }
    // SAFETY: tasklet storage is caller-owned and valid while scheduled.
    unsafe { if (*t).count.load(Ordering::Acquire) == 0 { if let Some(f) = (*t).func { f((*t).data); } } }
}
