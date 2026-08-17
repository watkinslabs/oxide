//! DRM fbdev-client setup and helper lifetime ABI.

use super::*;
use sync::{Modules as ModulesLockClass, Spinlock};

const LINUX_EINVAL: i32 = 22;
const LINUX_EOPNOTSUPP: i32 = 95;
const DRM_DRIVER_MODESET: u32 = 2;
const DRM_DEVICE_FEATURES_OFF: usize = 112;
const DRM_DEVICE_FB_HELPER_OFF: usize = 368;
const DRM_CLIENT_DEV_OFF: usize = 0;
const DRM_FB_HELPER_SIZE: usize = 424;
const DRM_FB_HELPER_DEV_OFF: usize = 112;
const DRM_FB_HELPER_FUNCS_OFF: usize = 120;
const DRM_FB_HELPER_INFO_OFF: usize = 128;
const DRM_FB_HELPER_PREFERRED_BPP_OFF: usize = 332;
const FORMAT_BYTES_PER_BLOCK_OFF: usize = 6;
const CLIENT_FUNCS_LEN: usize = 7;

struct ClientFuncsRecord { helper: usize, funcs: usize, layout: Layout }
static CLIENT_FUNCS: Spinlock<Vec<ClientFuncsRecord>, ModulesLockClass> = Spinlock::new(Vec::new());

pub(super) fn export_symbols() {
    crate::symtab::export("drm_client_setup", drm_client_setup as *const () as usize, false);
    crate::symtab::export("drm_client_setup_with_fourcc", drm_client_setup_with_fourcc as *const () as usize, false);
    crate::symtab::export("drm_client_setup_with_color_mode", drm_client_setup_with_color_mode as *const () as usize, false);
    crate::symtab::export("drm_fbdev_client_setup", drm_fbdev_client_setup as *const () as usize, false);
    crate::symtab::export("drm_fb_helper_prepare", drm_fb_helper_prepare as *const () as usize, false);
    crate::symtab::export("drm_fb_helper_unprepare", drm_fb_helper_unprepare as *const () as usize, false);
    crate::symtab::export("drm_fb_helper_init", drm_fb_helper_init as *const () as usize, false);
    crate::symtab::export("drm_fb_helper_fini", drm_fb_helper_fini as *const () as usize, false);
}

fn helper_layout() -> Layout { Layout::from_size_align(DRM_FB_HELPER_SIZE, core::mem::align_of::<u64>()).unwrap() }

fn new_client_funcs() -> Option<*mut usize> {
    let layout = Layout::array::<usize>(CLIENT_FUNCS_LEN).ok()?;
    // SAFETY: layout was computed and validated by Layout::array::<usize>(CLIENT_FUNCS_LEN) above.
    let funcs = unsafe { alloc_zeroed(layout).cast::<usize>() }; if funcs.is_null() { return None; }
    // SAFETY: funcs was allocated for CLIENT_FUNCS_LEN(7) usize slots above and indices
    // 1..6 are all within bounds.
    unsafe { write(funcs.add(1), fbdev_client_free as *const () as usize); write(funcs.add(2), fbdev_client_unregister as *const () as usize); write(funcs.add(3), fbdev_client_restore as *const () as usize); write(funcs.add(4), fbdev_client_hotplug as *const () as usize); write(funcs.add(5), fbdev_client_suspend as *const () as usize); write(funcs.add(6), fbdev_client_resume as *const () as usize); }
    Some(funcs)
}

fn release_client_funcs(helper: *mut c_void) {
    let record = { let mut records = CLIENT_FUNCS.lock(); records.iter().position(|record| record.helper == helper as usize).map(|index| records.remove(index)) };
    // SAFETY: record.funcs/layout is the exact allocation new_client_funcs made, removed
    // from CLIENT_FUNCS above before this free.
    if let Some(record) = record { unsafe { dealloc(record.funcs as *mut u8, record.layout); } }
}

fn modeset_capable(dev: *mut c_void) -> bool {
    // SAFETY: the preceding !dev.is_null() short-circuits before this read, so dev is non-null here.
    !dev.is_null() && unsafe { read(dev.cast::<u8>().add(DRM_DEVICE_FEATURES_OFF).cast::<u32>()) & DRM_DRIVER_MODESET != 0 }
}

fn helper_dev(helper: *mut c_void) -> *mut c_void {
    // SAFETY: helper was null-checked in this same expression and DRM_FB_HELPER_DEV_OFF
    // is its verified ABI field.
    if helper.is_null() { core::ptr::null_mut() } else { unsafe { read(helper.cast::<u8>().add(DRM_FB_HELPER_DEV_OFF).cast::<*mut c_void>()) } }
}

/// Prepare a driver-owned helper before client registration. # C: O(1)
pub(super) extern "C" fn drm_fb_helper_prepare(dev: *mut c_void, helper: *mut c_void, preferred_bpp: u32, funcs: *const c_void) {
    if dev.is_null() || helper.is_null() { return; }
    let bpp = if preferred_bpp == 0 { 32 } else { preferred_bpp };
    // SAFETY: helper is the complete caller-owned DRM fb-helper record and these stable fields are initialized before registration.
    unsafe { write(helper.cast::<u8>().add(DRM_FB_HELPER_DEV_OFF).cast::<*mut c_void>(), dev); write(helper.cast::<u8>().add(DRM_FB_HELPER_FUNCS_OFF).cast::<*const c_void>(), funcs); write(helper.cast::<u8>().add(DRM_FB_HELPER_PREFERRED_BPP_OFF).cast::<u32>(), bpp); }
}

/// Release the prepared-helper state after its client has gone away. # C: O(1)
pub(super) extern "C" fn drm_fb_helper_unprepare(helper: *mut c_void) {
    if helper.is_null() { return; }
    // SAFETY: helper remains caller-owned until its containing fbdev client free callback completes.
    unsafe { write(helper.cast::<u8>().add(DRM_FB_HELPER_FUNCS_OFF).cast::<*const c_void>(), core::ptr::null()); }
}

/// Associate a prepared helper with its live DRM device. # C: O(1)
pub(super) extern "C" fn drm_fb_helper_init(dev: *mut c_void, helper: *mut c_void) -> i32 {
    if dev.is_null() || helper.is_null() || helper_dev(helper) != dev { return -LINUX_EINVAL; }
    // SAFETY: dev is a live DRM device and fb_helper is its single canonical helper owner field.
    unsafe { write(dev.cast::<u8>().add(DRM_DEVICE_FB_HELPER_OFF).cast::<*mut c_void>(), helper); }
    0
}

/// Disassociate a helper and discard only core-owned helper state. # C: O(1)
pub(super) extern "C" fn drm_fb_helper_fini(helper: *mut c_void) {
    let dev = helper_dev(helper); if dev.is_null() { return; }
    // SAFETY: only clear the canonical device slot when it still names this helper, preserving a replacement helper.
    unsafe { let slot = dev.cast::<u8>().add(DRM_DEVICE_FB_HELPER_OFF).cast::<*mut c_void>(); if read(slot) == helper { write(slot, core::ptr::null_mut()); } write(helper.cast::<u8>().add(DRM_FB_HELPER_INFO_OFF).cast::<*mut c_void>(), core::ptr::null_mut()); }
}

// SAFETY: client is the exact helper allocation drm_fbdev_client_setup made with
// helper_layout(), released here as the client framework's free callback after its
// associated state was torn down above.
extern "C" fn fbdev_client_free(client: *mut c_void) { drm_fb_helper_fini(client); drm_fb_helper_unprepare(client); release_client_funcs(client); unsafe { dealloc(client.cast::<u8>(), helper_layout()); } }
extern "C" fn fbdev_client_unregister(client: *mut c_void) { client::drm_client_release(client); }
extern "C" fn fbdev_client_restore(_client: *mut c_void, _force: bool) -> i32 { 0 }
extern "C" fn fbdev_client_suspend(_client: *mut c_void) -> i32 { 0 }
extern "C" fn fbdev_client_resume(_client: *mut c_void) -> i32 { 0 }

extern "C" fn fbdev_client_hotplug(client: *mut c_void) -> i32 {
    // SAFETY: client is the live helper this callback's ABI slot receives from
    // drm_client_register/hotplug and DRM_CLIENT_DEV_OFF is the field drm_client_init
    // wrote at offset 0.
    let dev = unsafe { read(client.cast::<u8>().add(DRM_CLIENT_DEV_OFF).cast::<*mut c_void>()) };
    if drm_fb_helper_init(dev, client) != 0 { return -LINUX_EINVAL; }
    // The helper has claimed the canonical device slot. The remaining probe and
    // framebuffer publication contract is owned by drm_fbdev_shmem/DRM fbdev helpers.
    -LINUX_EOPNOTSUPP
}

/// Allocate and register the standard in-kernel fbdev client. # C: O(N_crtcs)
pub(super) extern "C" fn drm_fbdev_client_setup(dev: *mut c_void, format: *const u8) -> i32 {
    if !modeset_capable(dev) { return -LINUX_EOPNOTSUPP; }
    // SAFETY: helper_layout() is the fixed, pre-validated DRM_FB_HELPER_SIZE layout.
    let helper = unsafe { alloc_zeroed(helper_layout()) }; if helper.is_null() { return -LINUX_EOPNOTSUPP; }
    // SAFETY: helper is this call's own alloc_zeroed(helper_layout()) allocation from above,
    // freed here because new_client_funcs failed before it was ever published.
    let Some(funcs) = new_client_funcs() else { unsafe { dealloc(helper, helper_layout()); } return -LINUX_EOPNOTSUPP; };
    // SAFETY: format was null-checked in this branch and FORMAT_BYTES_PER_BLOCK_OFF is the
    // verified offset within a drm_format_info record.
    let bpp = if format.is_null() { 32 } else { unsafe { (*format.add(FORMAT_BYTES_PER_BLOCK_OFF) as u32).saturating_mul(8) } };
    drm_fb_helper_prepare(dev, helper.cast(), bpp, core::ptr::null());
    let name = c"fbdev";
    let rc = client::drm_client_init(dev, helper.cast(), name.as_ptr().cast(), funcs.cast());
    // SAFETY: funcs and helper are this call's own allocations from above, not yet pushed
    // to CLIENT_FUNCS, freed here because drm_client_init failed.
    if rc != 0 { drm_fb_helper_unprepare(helper.cast()); unsafe { dealloc(funcs.cast(), Layout::array::<usize>(CLIENT_FUNCS_LEN).unwrap()); dealloc(helper, helper_layout()); } return rc; }
    CLIENT_FUNCS.lock().push(ClientFuncsRecord { helper: helper as usize, funcs: funcs as usize, layout: Layout::array::<usize>(CLIENT_FUNCS_LEN).unwrap() });
    client::drm_client_register(helper.cast());
    0
}

/// Start the configured in-kernel client for a modeset DRM device. # C: O(N_crtcs)
pub(super) extern "C" fn drm_client_setup(dev: *mut c_void, format: *const u8) { if modeset_capable(dev) { let _ = drm_fbdev_client_setup(dev, format); } }

/// Start the configured in-kernel client from a fourcc preference. # C: O(N_crtcs)
pub(super) extern "C" fn drm_client_setup_with_fourcc(dev: *mut c_void, fourcc: u32) { drm_client_setup(dev, format::drm_format_info(fourcc).cast()); }

/// Start the configured in-kernel client from the legacy color-mode preference. # C: O(N_crtcs)
pub(super) extern "C" fn drm_client_setup_with_color_mode(dev: *mut c_void, color_mode: u32) { let fourcc = if color_mode == 16 { 0x3631_4752 } else { 0x3432_5258 }; drm_client_setup_with_fourcc(dev, fourcc); }

#[cfg(test)]
mod tests {
    use super::*;
    extern "C" fn dumb_create(_file: *mut c_void, _dev: *mut c_void, _args: *mut c_void) -> i32 { 0 }

    #[test]
    fn client_setup_allocates_registers_and_releases_one_fbdev_client() {
        let _serial = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let mut driver = [0u8; 104];
        // SAFETY: driver is this test's own [u8; 104] stack buffer and both offsets fall within it.
        unsafe { write(driver.as_mut_ptr().add(DRM_DRIVER_FEATURES_OFF).cast::<u32>(), DRM_DRIVER_MODESET); write(driver.as_mut_ptr().add(96).cast::<usize>(), dumb_create as *const () as usize); }
        let dev = super::__devm_drm_dev_alloc(&mut parent, driver.as_ptr().cast(), 2048, 0); assert_eq!(super::drmm_mode_config_init(dev), 0);
        drm_client_setup(dev, core::ptr::null());
        // SAFETY: dev is the live allocation returned by __devm_drm_dev_alloc above and
        // DRM_DEVICE_FB_HELPER_OFF is the verified device field.
        let helper = unsafe { read(dev.cast::<u8>().add(DRM_DEVICE_FB_HELPER_OFF).cast::<*mut c_void>()) }; assert!(!helper.is_null());
        // SAFETY: helper was null-checked above and DRM_FB_HELPER_PREFERRED_BPP_OFF is the
        // field drm_fb_helper_prepare wrote.
        assert_eq!(unsafe { read(helper.cast::<u8>().add(DRM_FB_HELPER_PREFERRED_BPP_OFF).cast::<u32>()) }, 32);
        // SAFETY: dev is the live allocation returned by __devm_drm_dev_alloc above and
        // DRM_DEVICE_FB_HELPER_OFF is the verified device field.
        super::register::drm_dev_unregister(dev); assert!(unsafe { read(dev.cast::<u8>().add(DRM_DEVICE_FB_HELPER_OFF).cast::<*mut c_void>()) }.is_null());
        devres::release_device(&mut parent);
    }
}
