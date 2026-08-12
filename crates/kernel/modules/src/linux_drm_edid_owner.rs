//! DRM opaque EDID allocation and ownership.

use super::*;
use alloc::alloc::{alloc, dealloc};

const EDID_LENGTH: usize = 128;
const DRM_EDID_SIZE_OFF: usize = 0;
const DRM_EDID_RAW_OFF: usize = 8;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_edid_alloc", drm_edid_alloc as *const () as usize, false);
    crate::symtab::export("drm_edid_dup", drm_edid_dup as *const () as usize, false);
    crate::symtab::export("drm_edid_free", drm_edid_free as *const () as usize, false);
    crate::symtab::export("drm_edid_raw", drm_edid_raw as *const () as usize, false);
}

/// Adopt a raw EDID allocation into the opaque two-word owner.  The caller
/// transfers ownership of `raw` regardless of whether this returns an owner.
pub(super) fn from_owned(raw: *mut u8, size: usize) -> *mut c_void {
    if raw.is_null() || size < EDID_LENGTH { return core::ptr::null_mut(); }
    let owner_layout = Layout::new::<[usize; 2]>();
    // SAFETY: the owner contains only the immutable allocation extent and its raw owner.
    let owner = unsafe { alloc(owner_layout) };
    if owner.is_null() {
        if let Ok(layout) = Layout::array::<u8>(size) { unsafe { dealloc(raw, layout); } }
        return core::ptr::null_mut();
    }
    // SAFETY: both opaque owner fields are initialized before publication.
    unsafe { write(owner.add(DRM_EDID_SIZE_OFF).cast::<usize>(), size); write(owner.add(DRM_EDID_RAW_OFF).cast::<*mut u8>(), raw); }
    owner.cast()
}

/// Allocate an opaque owner that duplicates at least one full EDID block. # C: O(size)
pub(super) extern "C" fn drm_edid_alloc(raw: *const c_void, size: usize) -> *mut c_void {
    if raw.is_null() || size < EDID_LENGTH { return core::ptr::null_mut(); }
    let Some(raw_layout) = Layout::array::<u8>(size).ok() else { return core::ptr::null_mut(); };
    // SAFETY: raw_layout owns a private byte-for-byte EDID copy before the owner is published.
    let copy = unsafe { alloc(raw_layout) }; if copy.is_null() { return core::ptr::null_mut(); }
    // SAFETY: raw supplies size readable EDID bytes and copy has exactly the same extent.
    unsafe { core::ptr::copy_nonoverlapping(raw.cast::<u8>(), copy, size); }
    let owner_layout = Layout::new::<[usize; 2]>();
    // SAFETY: owner has the exact opaque two-word external drm_edid representation.
    let owner = unsafe { alloc(owner_layout) }; if owner.is_null() { unsafe { dealloc(copy, raw_layout); } return core::ptr::null_mut(); }
    // SAFETY: both owner fields are initialized before returning the opaque owner pointer.
    unsafe { write(owner.add(DRM_EDID_SIZE_OFF).cast::<usize>(), size); write(owner.add(DRM_EDID_RAW_OFF).cast::<*mut u8>(), copy); }
    owner.cast()
}

/// Duplicate an existing opaque EDID owner. # C: O(size)
pub(super) extern "C" fn drm_edid_dup(owner: *const c_void) -> *mut c_void {
    let raw = drm_edid_raw(owner); if raw.is_null() { return core::ptr::null_mut(); }
    // SAFETY: drm_edid_raw validated that owner has a complete base block and its recorded allocation size.
    let size = unsafe { read(owner.cast::<u8>().add(DRM_EDID_SIZE_OFF).cast::<usize>()) };
    drm_edid_alloc(raw.cast(), size)
}

/// Return raw EDID only when the owner can contain its full declared extension count. # C: O(1)
pub(super) extern "C" fn drm_edid_raw(owner: *const c_void) -> *const u8 {
    if owner.is_null() { return core::ptr::null(); }
    // SAFETY: owner is the opaque pair created by drm_edid_alloc; fields are immutable until its sole free.
    let (size, raw) = unsafe { (read(owner.cast::<u8>().add(DRM_EDID_SIZE_OFF).cast::<usize>()), read(owner.cast::<u8>().add(DRM_EDID_RAW_OFF).cast::<*const u8>())) };
    if raw.is_null() || size < EDID_LENGTH { return core::ptr::null(); }
    // SAFETY: at least the base block is present, including the extension count byte at offset 126.
    let required = unsafe { (*raw.add(126) as usize).saturating_add(1).saturating_mul(EDID_LENGTH) };
    if required > size { core::ptr::null() } else { raw }
}

/// Free an EDID owner and its private raw-data allocation. # C: O(1)
pub(super) extern "C" fn drm_edid_free(owner: *mut c_void) {
    if owner.is_null() { return; }
    // SAFETY: owner is uniquely owned by the caller and was allocated as the exact opaque two-word record.
    let (size, raw) = unsafe { (read(owner.cast::<u8>().add(DRM_EDID_SIZE_OFF).cast::<usize>()), read(owner.cast::<u8>().add(DRM_EDID_RAW_OFF).cast::<*mut u8>())) };
    if !raw.is_null() { if let Ok(layout) = Layout::array::<u8>(size) { unsafe { dealloc(raw, layout); } } }
    // SAFETY: this is the matching allocation layout for the opaque owner record.
    unsafe { dealloc(owner.cast(), Layout::new::<[usize; 2]>()); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_duplicates_valid_data_and_rejects_truncated_extensions() {
        let mut raw = [0u8; EDID_LENGTH]; raw[126] = 0; raw[0] = 1;
        let owner = drm_edid_alloc(raw.as_ptr().cast(), raw.len()); assert!(!owner.is_null()); let copy = drm_edid_dup(owner); assert!(!copy.is_null()); raw[0] = 2;
        assert_eq!(unsafe { *drm_edid_raw(copy) }, 1); drm_edid_free(owner); drm_edid_free(copy);
        raw[126] = 1; let bad = drm_edid_alloc(raw.as_ptr().cast(), raw.len()); assert!(drm_edid_raw(bad).is_null()); drm_edid_free(bad);
    }
    #[test]
    fn owner_entry_points_are_module_exports() { export_symbols(); for name in ["drm_edid_alloc", "drm_edid_dup", "drm_edid_free", "drm_edid_raw"] { assert!(crate::symtab::is_exported(name)); } }
}
