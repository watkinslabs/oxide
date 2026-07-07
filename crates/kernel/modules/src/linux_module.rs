// Linux module owner/refcount compatibility exports.

use core::ffi::c_char;
use core::sync::atomic::{AtomicU32, Ordering};

const MODULE_STATE_LIVE: usize = 0;
const MODULE_STATE_COMING: usize = 1;
const MODULE_STATE_GOING: usize = 2;

#[repr(C)]
struct LinuxModule {
    name:   *const c_char,
    state:  usize,
    refcnt: u32,
}

/// Register Linux module lifecycle KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("try_module_get", try_module_get as *const () as usize),
        ("module_put",     module_put     as *const () as usize),
    ] { export(name, addr, false); }
}

unsafe extern "C" fn try_module_get(module: *mut LinuxModule) -> i32 {
    if module.is_null() { return 1; }
    let state = unsafe { core::ptr::read_volatile(&(*module).state) };
    if state == MODULE_STATE_GOING { return 0; }
    if state != MODULE_STATE_LIVE && state != MODULE_STATE_COMING { return 0; }
    // SAFETY: module points at Linux module storage whose refcnt field is u32-aligned.
    let r = unsafe { refcnt(module) };
    r.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1)).is_ok() as i32
}

unsafe extern "C" fn module_put(module: *mut LinuxModule) {
    if module.is_null() { return; }
    // SAFETY: module points at Linux module storage whose refcnt field is u32-aligned.
    let r = unsafe { refcnt(module) };
    let _ = r.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
}

unsafe fn refcnt(module: *mut LinuxModule) -> &'static AtomicU32 {
    // SAFETY: LinuxModule is repr(C), refcnt is naturally aligned, and caller proves module lifetime.
    unsafe { &*((&mut (*module).refcnt as *mut u32).cast::<AtomicU32>()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null;

    fn module(state: usize, refcnt: u32) -> LinuxModule {
        LinuxModule { name: null(), state, refcnt }
    }

    #[test]
    fn null_owner_is_builtin_and_gettable() {
        let got = unsafe { try_module_get(core::ptr::null_mut()) };
        assert_eq!(got, 1);
        unsafe { module_put(core::ptr::null_mut()) };
    }

    #[test]
    fn live_and_coming_modules_are_refcounted() {
        for state in [MODULE_STATE_LIVE, MODULE_STATE_COMING] {
            let mut m = module(state, 1);
            assert_eq!(unsafe { try_module_get(&mut m) }, 1);
            assert_eq!(m.refcnt, 2);
            unsafe { module_put(&mut m) };
            assert_eq!(m.refcnt, 1);
        }
    }

    #[test]
    fn going_or_unknown_modules_refuse_new_refs() {
        for state in [MODULE_STATE_GOING, 99] {
            let mut m = module(state, 4);
            assert_eq!(unsafe { try_module_get(&mut m) }, 0);
            assert_eq!(m.refcnt, 4);
        }
    }

    #[test]
    fn saturated_modules_refuse_new_refs() {
        let mut m = module(MODULE_STATE_LIVE, u32::MAX);
        assert_eq!(unsafe { try_module_get(&mut m) }, 0);
        assert_eq!(m.refcnt, u32::MAX);
    }

    #[test]
    fn module_put_saturates_at_zero() {
        let mut m = module(MODULE_STATE_LIVE, 0);
        unsafe { module_put(&mut m) };
        assert_eq!(m.refcnt, 0);
    }
}
