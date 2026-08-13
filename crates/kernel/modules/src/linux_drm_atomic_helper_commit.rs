//! DRM generic atomic commit dispatch.

use super::*;

const DEV_OFF: usize = 8; const FLAGS_OFF: usize = 16; const MODE_CONFIG_OFF: usize = 360; const HELPER_PRIVATE_OFF: usize = 1120;
const ASYNC_UPDATE: u8 = 1 << 2; const LINUX_EOPNOTSUPP: i32 = 95;

fn tail(dev: *mut u8) -> usize {
    // SAFETY: BTF-verified mode-config helper pointer and its first callback slot remain live through commit.
    unsafe { let helpers = read(dev.add(MODE_CONFIG_OFF + HELPER_PRIVATE_OFF).cast::<*const u8>()); if helpers.is_null() { 0 } else { read(helpers.cast::<usize>()) } }
}

pub(super) fn export_symbols() { crate::symtab::export("drm_atomic_helper_commit", drm_atomic_helper_commit as *const () as usize, false); }

/// Submit one validated atomic state through the generic synchronous commit sequence. # C: O(N_objects)
pub(super) extern "C" fn drm_atomic_helper_commit(dev: *mut c_void, state: *mut c_void, nonblock: bool) -> i32 {
    if dev.is_null() || state.is_null() { return -LINUX_EOPNOTSUPP; }
    let bytes = state.cast::<u8>();
    // SAFETY: every state retains the device that allocated it through its terminal put.
    if unsafe { read(bytes.add(DEV_OFF).cast::<*mut c_void>()) } != dev { return -LINUX_EOPNOTSUPP; }
    // SAFETY: flags are transaction-private while the caller owns this atomic state.
    if unsafe { read(bytes.add(FLAGS_OFF)) & ASYNC_UPDATE != 0 } {
        let ret = atomic_prepare::drm_atomic_helper_prepare_planes(dev, state); if ret != 0 { return ret; }
        atomic_async::drm_atomic_helper_async_commit(dev, state);
        atomic_prepare::drm_atomic_helper_unprepare_planes(dev, state);
        return 0;
    }
    if nonblock { return -LINUX_EOPNOTSUPP; }
    let ret = atomic_commit_setup::drm_atomic_helper_setup_commit(state, false); if ret != 0 { return ret; }
    let ret = atomic_prepare::drm_atomic_helper_prepare_planes(dev, state); if ret != 0 { return ret; }
    let ret = atomic_swap::drm_atomic_helper_swap_state(state, true); if ret != 0 { atomic_prepare::drm_atomic_helper_unprepare_planes(dev, state); return ret; }
    let callback = tail(dev.cast());
    if callback != 0 {
        // SAFETY: driver helper-private tail callback receives the published transaction state.
        unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void)>(callback)(state); }
    } else { atomic_commit_tail::drm_atomic_helper_commit_tail(state); }
    atomic_commit_tail::drm_atomic_helper_commit_cleanup_done(state);
    0
}
