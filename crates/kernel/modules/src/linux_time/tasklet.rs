use core::ptr::null_mut;
use core::sync::atomic::Ordering;

use super::clock::now_ns;
use super::types::*;

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
    let _ = timer::register_oneshot(deadline, t as usize, tasklet_fire);
}

pub(super) extern "C" fn tasklet_kill(t: *mut LinuxTaskletStruct) {
    if !t.is_null() {
        // SAFETY: non-null pointer names caller-owned tasklet_struct storage.
        unsafe { (*t).state = 0; }
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
    let t = arg as *mut LinuxTaskletStruct;
    if t.is_null() { return; }
    // SAFETY: tasklet storage is caller-owned and valid while scheduled.
    unsafe { if (*t).count.load(Ordering::Acquire) == 0 { if let Some(f) = (*t).func { f((*t).data); } } }
}
