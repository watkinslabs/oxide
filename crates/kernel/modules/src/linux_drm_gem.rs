//! DRM generic private-GEM objects and per-file handles.

use super::*;
use alloc::alloc::alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::alloc::Layout;

const LINUX_EBUSY: i32 = 16;
const LINUX_EINVAL: i32 = 22;
const DRM_FILE_OBJECT_IDR_HEAD_OFF: usize = 88;
const DRM_GEM_REFCOUNT_OFF: usize = 0;
const DRM_GEM_HANDLE_COUNT_OFF: usize = 4;
const DRM_GEM_DEVICE_OFF: usize = 8;
const DRM_GEM_FILP_OFF: usize = 16;
const DRM_GEM_SIZE_OFF: usize = 216;
const DRM_GEM_OBJECT_FUNCS_OFF: usize = 352;
const DRM_GEM_FUNCS_CLOSE_OFF: usize = 16;
const INITIAL_REFERENCE_COUNT: i32 = 1;

struct GemHandle { handle: u32, object: usize }

struct GemFile { next: u32, handles: Vec<GemHandle> }

type GemClose = unsafe extern "C" fn(*mut c_void, *mut c_void);

pub(super) fn export_symbols() {
    crate::symtab::export("drm_gem_private_object_init", drm_gem_private_object_init as *const () as usize, false);
    crate::symtab::export("drm_gem_object_release", drm_gem_object_release as *const () as usize, false);
    crate::symtab::export("drm_gem_handle_create", drm_gem_handle_create as *const () as usize, false);
    crate::symtab::export("drm_gem_handle_delete", drm_gem_handle_delete as *const () as usize, false);
    crate::symtab::export("drm_gem_object_lookup", drm_gem_object_lookup as *const () as usize, false);
    crate::symtab::export("drm_gem_release", drm_gem_release as *const () as usize, false);
}

/// Initialize the exact `drm_file.object_idr` owner used by GEM handles.
/// # C: O(1)
pub(super) fn file_init(file: *mut c_void) -> bool {
    if file.is_null() { return false; }
    let layout = Layout::new::<GemFile>();
    // SAFETY: layout describes exactly the file-owned handle state and is reclaimed via Box::from_raw.
    let raw = unsafe { alloc(layout).cast::<GemFile>() };
    if raw.is_null() { return false; }
    // SAFETY: raw is a newly allocated, properly aligned GemFile slot and is initialized exactly once.
    unsafe { write(raw, GemFile { next: 1, handles: Vec::new() }); }
    // SAFETY: file is the complete ABI-sized drm_file allocation; the xarray root
    // field is reserved for the file's object-IDR owner and starts zeroed at open.
    unsafe { write(file.cast::<u8>().add(DRM_FILE_OBJECT_IDR_HEAD_OFF).cast::<*mut GemFile>(), raw); }
    true
}

/// Release every file-private GEM handle before its `drm_file` allocation disappears.
/// # C: O(N_handles)
pub(super) fn file_release(_dev: *mut c_void, file: *mut c_void) {
    if file.is_null() { return; }
    // SAFETY: file remains owned by drm_release; this reads and clears the same
    // object-IDR root installed by file_init before dropping its exact Box allocation.
    let state = unsafe { read(file.cast::<u8>().add(DRM_FILE_OBJECT_IDR_HEAD_OFF).cast::<*mut GemFile>()) };
    if state.is_null() { return; }
    // SAFETY: no caller may retain the file after release, so the unique owner may drain it.
    let mut state = unsafe { Box::from_raw(state) };
    for entry in state.handles.drain(..) { release_handle(entry.object as *mut c_void, file); }
    // SAFETY: clearing prevents a second release from recovering the already freed owner.
    unsafe { write(file.cast::<u8>().add(DRM_FILE_OBJECT_IDR_HEAD_OFF).cast::<*mut GemFile>(), core::ptr::null_mut()); }
}

fn state(file: *mut c_void) -> Option<&'static mut GemFile> {
    if file.is_null() { return None; }
    // SAFETY: the object-IDR root is initialized at drm_open and survives until file_release.
    let raw = unsafe { read(file.cast::<u8>().add(DRM_FILE_OBJECT_IDR_HEAD_OFF).cast::<*mut GemFile>()) };
    if raw.is_null() { None } else { Some(unsafe { &mut *raw }) }
}

/// Initialize a driver-owned GEM object with private backing. # C: O(1)
pub(super) extern "C" fn drm_gem_private_object_init(dev: *mut c_void, object: *mut c_void, size: usize) {
    if dev.is_null() || object.is_null() || size == 0 { return; }
    // SAFETY: caller supplies the verified complete embedded drm_gem_object; these
    // fields are its stable object-lifetime scalars and are initialized once before use.
    unsafe {
        write(object.cast::<u8>().add(DRM_GEM_REFCOUNT_OFF).cast::<i32>(), INITIAL_REFERENCE_COUNT);
        write(object.cast::<u8>().add(DRM_GEM_HANDLE_COUNT_OFF).cast::<u32>(), 0);
        write(object.cast::<u8>().add(DRM_GEM_DEVICE_OFF).cast::<*mut c_void>(), dev);
        write(object.cast::<u8>().add(DRM_GEM_FILP_OFF).cast::<*mut c_void>(), core::ptr::null_mut());
        write(object.cast::<u8>().add(DRM_GEM_SIZE_OFF).cast::<usize>(), size);
    }
}

/// Release generic GEM object state after the driver has released its backing store. # C: O(1)
pub(super) extern "C" fn drm_gem_object_release(object: *mut c_void) {
    if object.is_null() { return; }
    // SAFETY: object remains driver-owned; release clears only the generic fields initialized above.
    unsafe {
        write(object.cast::<u8>().add(DRM_GEM_FILP_OFF).cast::<*mut c_void>(), core::ptr::null_mut());
        write(object.cast::<u8>().add(DRM_GEM_HANDLE_COUNT_OFF).cast::<u32>(), 0);
    }
}

/// Publish a fully initialized GEM object as a new handle on this DRM file. # C: O(N_handles)
pub(super) extern "C" fn drm_gem_handle_create(file: *mut c_void, object: *mut c_void, out: *mut u32) -> i32 {
    if object.is_null() || out.is_null() { return -LINUX_EINVAL; }
    let Some(state) = state(file) else { return -LINUX_EINVAL; };
    let handle = state.next;
    if handle == 0 { return -LINUX_EBUSY; }
    state.next = handle.checked_add(1).unwrap_or(0);
    state.handles.push(GemHandle { handle, object: object as usize });
    // SAFETY: object is now published to this file and handle_count records that ownership.
    unsafe { let count = read(object.cast::<u8>().add(DRM_GEM_HANDLE_COUNT_OFF).cast::<u32>()); write(object.cast::<u8>().add(DRM_GEM_HANDLE_COUNT_OFF).cast::<u32>(), count.saturating_add(1)); write(out, handle); }
    0
}

/// Delete one file-private GEM handle and invoke its driver close hook. # C: O(N_handles)
pub(super) extern "C" fn drm_gem_handle_delete(file: *mut c_void, handle: u32) -> i32 {
    let Some(state) = state(file) else { return -LINUX_EINVAL; };
    let Some(pos) = state.handles.iter().position(|entry| entry.handle == handle) else { return -LINUX_EINVAL; };
    let entry = state.handles.remove(pos); release_handle(entry.object as *mut c_void, file); 0
}

/// Look up a handle owned by this DRM file. # C: O(N_handles)
pub(super) extern "C" fn drm_gem_object_lookup(file: *mut c_void, handle: u32) -> *mut c_void {
    let Some(state) = state(file) else { return core::ptr::null_mut(); };
    state.handles.iter().find(|entry| entry.handle == handle).map_or(core::ptr::null_mut(), |entry| entry.object as *mut c_void)
}

/// Release all file-private GEM references. # C: O(N_handles)
pub(super) extern "C" fn drm_gem_release(dev: *mut c_void, file: *mut c_void) { file_release(dev, file); }

fn release_handle(object: *mut c_void, file: *mut c_void) {
    if object.is_null() { return; }
    // SAFETY: funcs is the ABI function table selected by the driver; close is optional.
    let funcs = unsafe { read(object.cast::<u8>().add(DRM_GEM_OBJECT_FUNCS_OFF).cast::<*const u8>()) };
    if !funcs.is_null() {
        // SAFETY: a non-null close slot has the external DRM object-close signature.
        let close = unsafe { read(funcs.add(DRM_GEM_FUNCS_CLOSE_OFF).cast::<Option<GemClose>>()) };
        if let Some(close) = close { unsafe { close(object, file); } }
    }
    // SAFETY: this handle's reference is removed exactly once from the file owner's vector.
    unsafe { let count = read(object.cast::<u8>().add(DRM_GEM_HANDLE_COUNT_OFF).cast::<u32>()); write(object.cast::<u8>().add(DRM_GEM_HANDLE_COUNT_OFF).cast::<u32>(), count.saturating_sub(1)); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_file_owned_and_close_once() {
        let mut file = [0u8; 416]; let mut object = [0u8; 384]; let mut dev = [0u8; 64]; let mut handle = 0;
        assert!(file_init(file.as_mut_ptr().cast())); drm_gem_private_object_init(dev.as_mut_ptr().cast(), object.as_mut_ptr().cast(), 4096);
        // SAFETY: the test object reserves the complete ABI object and was initialized above.
        unsafe { assert_eq!(read(object.as_ptr().add(DRM_GEM_DEVICE_OFF).cast::<*mut c_void>()), dev.as_mut_ptr().cast()); assert_eq!(read(object.as_ptr().add(DRM_GEM_SIZE_OFF).cast::<usize>()), 4096); }
        assert_eq!(drm_gem_handle_create(file.as_mut_ptr().cast(), object.as_mut_ptr().cast(), &mut handle), 0); assert_eq!(handle, 1);
        assert_eq!(drm_gem_object_lookup(file.as_mut_ptr().cast(), handle), object.as_mut_ptr().cast()); assert_eq!(drm_gem_handle_delete(file.as_mut_ptr().cast(), handle), 0);
        assert!(drm_gem_object_lookup(file.as_mut_ptr().cast(), handle).is_null()); assert_eq!(drm_gem_handle_delete(file.as_mut_ptr().cast(), handle), -LINUX_EINVAL); file_release(dev.as_mut_ptr().cast(), file.as_mut_ptr().cast());
    }

    #[test]
    fn generic_gem_entry_points_are_module_exports() {
        export_symbols();
        for name in ["drm_gem_private_object_init", "drm_gem_object_release", "drm_gem_handle_create", "drm_gem_handle_delete", "drm_gem_object_lookup", "drm_gem_release"] { assert!(crate::symtab::is_exported(name)); }
    }
}
