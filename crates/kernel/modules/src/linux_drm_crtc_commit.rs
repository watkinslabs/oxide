//! DRM CRTC commit completion and reference ownership.

use super::*;
use alloc::alloc::{alloc_zeroed, dealloc};

const DRM_CRTC_COMMIT_SIZE: usize = 144;
const DRM_CRTC_COMMIT_CRTC_OFF: usize = 0;
const DRM_CRTC_COMMIT_REF_OFF: usize = 8;
const DRM_CRTC_COMMIT_FLIP_DONE_OFF: usize = 16;
const DRM_CRTC_COMMIT_HW_DONE_OFF: usize = 48;
const DRM_CRTC_COMMIT_CLEANUP_DONE_OFF: usize = 80;
const DRM_CRTC_COMMIT_ENTRY_OFF: usize = 112;
const COMMIT_WAIT_JIFFIES: usize = 1_000;
const LINUX_ETIMEDOUT: i32 = 110;

fn layout() -> Layout { Layout::from_size_align(DRM_CRTC_COMMIT_SIZE, core::mem::align_of::<u64>()).unwrap() }

pub(crate) fn alloc(crtc: *mut c_void) -> *mut u8 {
    // SAFETY: layout names the complete CRTC commit ABI object and is initialized before publication.
    let commit = unsafe { alloc_zeroed(layout()) };
    if commit.is_null() { return core::ptr::null_mut(); }
    // SAFETY: every offset names an aligned member in the complete fresh CRTC commit record.
    unsafe {
        write(commit.add(DRM_CRTC_COMMIT_CRTC_OFF).cast::<*mut c_void>(), crtc);
        crate::linux_sync::kref_init(commit.add(DRM_CRTC_COMMIT_REF_OFF).cast());
        crate::linux_sync::init_completion(commit.add(DRM_CRTC_COMMIT_FLIP_DONE_OFF).cast());
        crate::linux_sync::init_completion(commit.add(DRM_CRTC_COMMIT_HW_DONE_OFF).cast());
        crate::linux_sync::init_completion(commit.add(DRM_CRTC_COMMIT_CLEANUP_DONE_OFF).cast());
        let entry = commit.add(DRM_CRTC_COMMIT_ENTRY_OFF); write(entry.cast::<*mut u8>(), entry); write(entry.add(core::mem::size_of::<*mut u8>()).cast::<*mut u8>(), entry);
    }
    commit
}

pub(crate) fn get(commit: *mut u8) -> *mut u8 {
    if commit.is_null() { return core::ptr::null_mut(); }
    // SAFETY: a live commit owns its embedded kref at the fixed ABI offset.
    unsafe { crate::linux_sync::kref_get(commit.add(DRM_CRTC_COMMIT_REF_OFF).cast()); }
    commit
}

pub(crate) fn put(commit: *mut u8) {
    if commit.is_null() { return; }
    // SAFETY: the caller owns one reference to this live commit and this release callback frees only its containing allocation.
    unsafe { crate::linux_sync::kref_put(commit.add(DRM_CRTC_COMMIT_REF_OFF).cast(), Some(__drm_crtc_commit_free)); }
}

pub(super) fn export_symbols() {
    crate::symtab::export("__drm_crtc_commit_free", __drm_crtc_commit_free as *const () as usize, false);
    crate::symtab::export("drm_crtc_commit_wait", drm_crtc_commit_wait as *const () as usize, false);
}

/// Release a zero-referenced CRTC commit allocation. # C: O(1)
pub(super) extern "C" fn __drm_crtc_commit_free(kref: *mut crate::linux_sync::LinuxKref) {
    if kref.is_null() { return; }
    // SAFETY: kref is embedded at byte 8 of the exact allocation created by `alloc`.
    let commit = unsafe { kref.cast::<u8>().sub(DRM_CRTC_COMMIT_REF_OFF) };
    // SAFETY: the final kref release uniquely owns this allocation and its exact ABI layout.
    unsafe { dealloc(commit, layout()); }
}

/// Wait until a commit has reached hardware and flip completion. # C: O(1)
pub(super) extern "C" fn drm_crtc_commit_wait(commit: *mut c_void) -> i32 {
    if commit.is_null() { return 0; }
    let commit = commit.cast::<u8>();
    // SAFETY: each completion occupies its ABI-pinned position in the live commit record.
    let hw_done = unsafe { commit.add(DRM_CRTC_COMMIT_HW_DONE_OFF).cast::<crate::linux_sync::LinuxCompletion>() };
    if crate::linux_sync::wait_for_completion_timeout(hw_done, COMMIT_WAIT_JIFFIES) == 0 { return -LINUX_ETIMEDOUT; }
    // SAFETY: flip_done remains valid after the preceding hardware completion wait.
    let flip_done = unsafe { commit.add(DRM_CRTC_COMMIT_FLIP_DONE_OFF).cast::<crate::linux_sync::LinuxCompletion>() };
    if crate::linux_sync::wait_for_completion_timeout(flip_done, COMMIT_WAIT_JIFFIES) == 0 { return -LINUX_ETIMEDOUT; }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_wait_requires_hardware_then_flip_completion() {
        let _modules = crate::test_serial::claim();
        let commit = alloc(1usize as *mut c_void); assert!(!commit.is_null());
        assert_eq!(drm_crtc_commit_wait(commit.cast()), -LINUX_ETIMEDOUT);
        // SAFETY: the fresh commit contains the two tested completion fields at their ABI offsets.
        unsafe { crate::linux_sync::complete(commit.add(DRM_CRTC_COMMIT_HW_DONE_OFF).cast()); }
        assert_eq!(drm_crtc_commit_wait(commit.cast()), -LINUX_ETIMEDOUT);
        // SAFETY: reinitialize hardware completion because the preceding wait consumed its one completion token.
        unsafe { crate::linux_sync::complete(commit.add(DRM_CRTC_COMMIT_HW_DONE_OFF).cast()); crate::linux_sync::complete(commit.add(DRM_CRTC_COMMIT_FLIP_DONE_OFF).cast()); }
        assert_eq!(drm_crtc_commit_wait(commit.cast()), 0); put(commit);
    }

    #[test]
    fn commit_exports_and_reference_pair_release_once() {
        let _modules = crate::test_serial::claim(); export_symbols(); assert!(crate::symtab::is_exported("__drm_crtc_commit_free")); assert!(crate::symtab::is_exported("drm_crtc_commit_wait"));
        let commit = alloc(core::ptr::null_mut()); assert_eq!(get(commit), commit); put(commit); put(commit);
    }
}
