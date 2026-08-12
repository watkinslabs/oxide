//! DRM generic private-GEM objects and per-file handles.

use super::*;
use alloc::alloc::{alloc, alloc_zeroed, dealloc};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::alloc::Layout;

const LINUX_EBUSY: i32 = 16;
const LINUX_EINVAL: i32 = 22;
const PAGE_SIZE: u64 = 4096;
const DRM_GEM_OBJECT_SIZE: usize = 384;
const DRM_GEM_SHMEM_OBJECT_SIZE: usize = 448;
const BITS_PER_BYTE: u64 = 8;
const DRM_DUMB_HEIGHT_OFF: usize = 0;
const DRM_DUMB_WIDTH_OFF: usize = 4;
const DRM_DUMB_BPP_OFF: usize = 8;
const DRM_DUMB_HANDLE_OFF: usize = 16;
const DRM_DUMB_PITCH_OFF: usize = 20;
const DRM_DUMB_SIZE_OFF: usize = 24;
const DRM_FILE_OBJECT_IDR_HEAD_OFF: usize = 88;
const DRM_GEM_REFCOUNT_OFF: usize = 0;
const DRM_GEM_HANDLE_COUNT_OFF: usize = 4;
const DRM_GEM_DEVICE_OFF: usize = 8;
const DRM_GEM_FILP_OFF: usize = 16;
const DRM_GEM_SIZE_OFF: usize = 216;
const DRM_GEM_OBJECT_FUNCS_OFF: usize = 352;
const DRM_GEM_FUNCS_CLOSE_OFF: usize = 16;
const DRM_GEM_FUNCS_FREE_OFF: usize = 0;
const DRM_GEM_SHMEM_VADDR_OFF: usize = 432;
const DRM_FB_SIZE: usize = 192;
const DRM_FB_FORMAT_OFF: usize = 72;
const DRM_FB_FUNCS_OFF: usize = 80;
const DRM_FB_PITCHES_OFF: usize = 88;
const DRM_FB_OFFSETS_OFF: usize = 104;
const DRM_FB_MODIFIER_OFF: usize = 120;
const DRM_FB_WIDTH_OFF: usize = 128;
const DRM_FB_HEIGHT_OFF: usize = 132;
const DRM_FB_FLAGS_OFF: usize = 136;
const DRM_FB_OBJECTS_OFF: usize = 160;
const DRM_FB_CMD_WIDTH_OFF: usize = 4;
const DRM_FB_CMD_HEIGHT_OFF: usize = 8;
const DRM_FB_CMD_FLAGS_OFF: usize = 16;
const DRM_FB_CMD_HANDLES_OFF: usize = 20;
const DRM_FB_CMD_PITCHES_OFF: usize = 36;
const DRM_FB_CMD_OFFSETS_OFF: usize = 52;
const DRM_FB_CMD_MODIFIERS_OFF: usize = 72;
const DRM_FORMAT_PLANES_OFF: usize = 5;
const INITIAL_REFERENCE_COUNT: i32 = 1;

struct GemHandle { handle: u32, object: usize }

struct GemFile { next: u32, handles: Vec<GemHandle> }

type GemClose = unsafe extern "C" fn(*mut c_void, *mut c_void);
type GemFree = unsafe extern "C" fn(*mut c_void);
type FbDestroy = unsafe extern "C" fn(*mut c_void);

static SHMEM_OBJECT_FUNCS: [Option<GemFree>; 3] = [Some(shmem_object_free), None, None];
static GEM_FB_FUNCS: [Option<FbDestroy>; 3] = [Some(gem_fb_destroy), None, None];

pub(super) fn export_symbols() {
    crate::symtab::export("drm_gem_private_object_init", drm_gem_private_object_init as *const () as usize, false);
    crate::symtab::export("drm_gem_object_release", drm_gem_object_release as *const () as usize, false);
    crate::symtab::export("drm_gem_handle_create", drm_gem_handle_create as *const () as usize, false);
    crate::symtab::export("drm_gem_handle_delete", drm_gem_handle_delete as *const () as usize, false);
    crate::symtab::export("drm_gem_object_lookup", drm_gem_object_lookup as *const () as usize, false);
    crate::symtab::export("drm_gem_release", drm_gem_release as *const () as usize, false);
    crate::symtab::export("drm_mode_size_dumb", drm_mode_size_dumb as *const () as usize, false);
    crate::symtab::export("drm_gem_shmem_dumb_create", drm_gem_shmem_dumb_create as *const () as usize, false);
    crate::symtab::export("drm_gem_fb_create_with_dirty", drm_gem_fb_create_with_dirty as *const () as usize, false);
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
    // SAFETY: the newly published handle obtains one object reference and increments its handle count.
    unsafe { let refs = read(object.cast::<u8>().add(DRM_GEM_REFCOUNT_OFF).cast::<i32>()); let count = read(object.cast::<u8>().add(DRM_GEM_HANDLE_COUNT_OFF).cast::<u32>()); write(object.cast::<u8>().add(DRM_GEM_REFCOUNT_OFF).cast::<i32>(), refs.saturating_add(1)); write(object.cast::<u8>().add(DRM_GEM_HANDLE_COUNT_OFF).cast::<u32>(), count.saturating_add(1)); write(out, handle); }
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
    let Some(entry) = state.handles.iter().find(|entry| entry.handle == handle) else { return core::ptr::null_mut(); };
    let object = entry.object as *mut c_void;
    // SAFETY: the file owns one live handle reference and lookup obtains an additional temporary reference.
    unsafe { let refs = read(object.cast::<u8>().add(DRM_GEM_REFCOUNT_OFF).cast::<i32>()); write(object.cast::<u8>().add(DRM_GEM_REFCOUNT_OFF).cast::<i32>(), refs.saturating_add(1)); }
    object
}

/// Release all file-private GEM references. # C: O(N_handles)
pub(super) extern "C" fn drm_gem_release(dev: *mut c_void, file: *mut c_void) { file_release(dev, file); }

/// Calculate a page-mappable dumb-buffer pitch and size. # C: O(1)
pub(super) extern "C" fn drm_mode_size_dumb(_dev: *mut c_void, args: *mut c_void, pitch_align: usize, size_align: usize) -> i32 {
    if args.is_null() { return -LINUX_EINVAL; }
    // SAFETY: args is the complete drm_mode_create_dumb ABI record supplied by the caller.
    let (height, width, bpp) = unsafe { (read(args.cast::<u8>().add(DRM_DUMB_HEIGHT_OFF).cast::<u32>()) as u64, read(args.cast::<u8>().add(DRM_DUMB_WIDTH_OFF).cast::<u32>()) as u64, read(args.cast::<u8>().add(DRM_DUMB_BPP_OFF).cast::<u32>()) as u64) };
    if width == 0 || height == 0 || bpp == 0 { return -LINUX_EINVAL; }
    let bytes_per_pixel = bpp.checked_add(BITS_PER_BYTE - 1).map(|v| v / BITS_PER_BYTE).unwrap_or(0);
    let mut pitch = width.checked_mul(bytes_per_pixel).filter(|v| *v <= u32::MAX as u64).unwrap_or(0);
    if pitch == 0 { return -LINUX_EINVAL; }
    if pitch_align != 0 { let align = pitch_align as u64; pitch = align_up(pitch, align).unwrap_or(0); if pitch < align { return -LINUX_EINVAL; } }
    let align = if size_align == 0 { PAGE_SIZE } else { size_align as u64 };
    if align == 0 || align % PAGE_SIZE != 0 { return -LINUX_EINVAL; }
    let size = height.checked_mul(pitch).and_then(|v| align_up(v, align)).filter(|v| *v != 0 && *v <= u32::MAX as u64);
    let Some(size) = size else { return -LINUX_EINVAL; };
    // SAFETY: pitch and size are the two output fields of the same verified dumb-buffer ABI record.
    unsafe { write(args.cast::<u8>().add(DRM_DUMB_PITCH_OFF).cast::<u32>(), pitch as u32); write(args.cast::<u8>().add(DRM_DUMB_SIZE_OFF).cast::<u64>(), size); }
    0
}

/// Create a page-backed shmem dumb buffer and publish its one file handle. # C: O(size)
pub(super) extern "C" fn drm_gem_shmem_dumb_create(file: *mut c_void, dev: *mut c_void, args: *mut c_void) -> i32 {
    let rc = drm_mode_size_dumb(dev, args, 0, 0); if rc != 0 { return rc; }
    // SAFETY: sizing succeeded and wrote the exact u64 size field in args.
    let size = unsafe { read(args.cast::<u8>().add(DRM_DUMB_SIZE_OFF).cast::<u64>()) };
    let Ok(size) = usize::try_from(size) else { return -LINUX_EBUSY; };
    let Some(backing_layout) = Layout::from_size_align(size, PAGE_SIZE as usize).ok() else { return -LINUX_EBUSY; };
    let object_layout = Layout::from_size_align(DRM_GEM_SHMEM_OBJECT_SIZE, core::mem::align_of::<u64>()).unwrap();
    // SAFETY: both layouts were validated and every failure below releases exactly its allocation.
    let object = unsafe { alloc_zeroed(object_layout) };
    if object.is_null() { return -LINUX_EBUSY; }
    // SAFETY: backing is page-aligned zeroed memory owned by this shmem object until its free callback.
    let backing = unsafe { alloc_zeroed(backing_layout) };
    if backing.is_null() { unsafe { dealloc(object, object_layout); } return -LINUX_EBUSY; }
    drm_gem_private_object_init(dev, object.cast(), size);
    // SAFETY: object reserves the complete shmem-GEM ABI record; these fields install its backing and free contract.
    unsafe { write(object.add(DRM_GEM_OBJECT_FUNCS_OFF).cast::<*const Option<GemFree>>(), SHMEM_OBJECT_FUNCS.as_ptr()); write(object.add(DRM_GEM_SHMEM_VADDR_OFF).cast::<*mut u8>(), backing); }
    // SAFETY: args owns the user-visible handle output, populated only after the object is fully initialized.
    let out = unsafe { args.cast::<u8>().add(DRM_DUMB_HANDLE_OFF).cast::<u32>() };
    let rc = drm_gem_handle_create(file, object.cast(), out);
    if rc != 0 { unsafe { dealloc(backing, backing_layout); dealloc(object, object_layout); } return rc; }
    object_put(object.cast()); 0
}

/// Build a GEM-backed framebuffer with the atomic dirty callback contract. # C: O(N_planes)
pub(super) extern "C" fn drm_gem_fb_create_with_dirty(dev: *mut c_void, file: *mut c_void, info: *const u8, cmd: *const u8) -> *mut c_void {
    if dev.is_null() || file.is_null() || info.is_null() || cmd.is_null() { return err_ptr(LINUX_EINVAL); }
    // SAFETY: info is the external immutable format descriptor and num_planes is its verified byte field.
    let planes = unsafe { *info.add(DRM_FORMAT_PLANES_OFF) as usize };
    if planes == 0 || planes > 4 { return err_ptr(LINUX_EINVAL); }
    let layout = Layout::from_size_align(DRM_FB_SIZE, core::mem::align_of::<u64>()).unwrap();
    // SAFETY: framebuffer layout is the verified complete external DRM framebuffer object.
    let fb = unsafe { alloc_zeroed(layout) };
    if fb.is_null() { return err_ptr(LINUX_EBUSY); }
    // SAFETY: cmd is a complete drm_mode_fb_cmd2 record whose scalar and plane arrays use these ABI offsets.
    unsafe {
        write(fb.cast::<*mut c_void>(), dev); write(fb.add(DRM_FB_FORMAT_OFF).cast::<*const u8>(), info); write(fb.add(DRM_FB_FUNCS_OFF).cast::<*const Option<FbDestroy>>(), GEM_FB_FUNCS.as_ptr());
        write(fb.add(DRM_FB_WIDTH_OFF).cast::<u32>(), read(cmd.add(DRM_FB_CMD_WIDTH_OFF).cast::<u32>())); write(fb.add(DRM_FB_HEIGHT_OFF).cast::<u32>(), read(cmd.add(DRM_FB_CMD_HEIGHT_OFF).cast::<u32>())); write(fb.add(DRM_FB_FLAGS_OFF).cast::<u32>(), read(cmd.add(DRM_FB_CMD_FLAGS_OFF).cast::<u32>())); write(fb.add(DRM_FB_MODIFIER_OFF).cast::<u64>(), read(cmd.add(DRM_FB_CMD_MODIFIERS_OFF).cast::<u64>()));
    }
    for plane in 0..planes {
        // SAFETY: plane is bounded by DRM_FORMAT_MAX_PLANES and all indexed cmd/fb fields lie in their fixed arrays.
        let (handle, pitch, offset) = unsafe { (read(cmd.add(DRM_FB_CMD_HANDLES_OFF + plane * 4).cast::<u32>()), read(cmd.add(DRM_FB_CMD_PITCHES_OFF + plane * 4).cast::<u32>()), read(cmd.add(DRM_FB_CMD_OFFSETS_OFF + plane * 4).cast::<u32>())) };
        let object = drm_gem_object_lookup(file, handle); if object.is_null() { unsafe { gem_fb_destroy(fb.cast()); } return err_ptr(LINUX_EINVAL); }
        // SAFETY: format helper accepts the verified format object and plane index; command width/height are fixed scalar fields.
        let (width, height, min_pitch) = unsafe { (read(cmd.add(DRM_FB_CMD_WIDTH_OFF).cast::<u32>()), read(cmd.add(DRM_FB_CMD_HEIGHT_OFF).cast::<u32>()), format::drm_format_info_min_pitch(info, plane as i32, read(cmd.add(DRM_FB_CMD_WIDTH_OFF).cast::<u32>()))) };
        let required = (height as u64).saturating_sub(1).saturating_mul(pitch as u64).saturating_add(min_pitch).saturating_add(offset as u64);
        // SAFETY: object is a live lookup reference and its size field is immutable for its lifetime.
        if pitch < min_pitch as u32 || required > unsafe { read(object.cast::<u8>().add(DRM_GEM_SIZE_OFF).cast::<usize>()) as u64 } { object_put(object); unsafe { gem_fb_destroy(fb.cast()); } return err_ptr(LINUX_EINVAL); }
        let _ = width;
        // SAFETY: framebuffer plane arrays are bounded by the checked format-plane count.
        unsafe { write(fb.add(DRM_FB_PITCHES_OFF + plane * 4).cast::<u32>(), pitch); write(fb.add(DRM_FB_OFFSETS_OFF + plane * 4).cast::<u32>(), offset); write(fb.add(DRM_FB_OBJECTS_OFF + plane * core::mem::size_of::<*mut c_void>()).cast::<*mut c_void>(), object); }
    }
    fb.cast()
}

fn err_ptr(errno: i32) -> *mut c_void { (-(errno as isize)) as usize as *mut c_void }

fn align_up(value: u64, align: u64) -> Option<u64> { value.checked_add(align.checked_sub(1)?).map(|v| v / align * align) }

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
    object_put(object);
}

fn object_put(object: *mut c_void) {
    // SAFETY: every caller holds exactly one previously acquired GEM object reference.
    let refs = unsafe { read(object.cast::<u8>().add(DRM_GEM_REFCOUNT_OFF).cast::<i32>()) };
    if refs <= 1 { object_free(object); } else { unsafe { write(object.cast::<u8>().add(DRM_GEM_REFCOUNT_OFF).cast::<i32>(), refs - 1); } }
}

fn object_free(object: *mut c_void) {
    // SAFETY: funcs is the complete object callback table and its first field is the optional free callback.
    let funcs = unsafe { read(object.cast::<u8>().add(DRM_GEM_OBJECT_FUNCS_OFF).cast::<*const u8>()) };
    if funcs.is_null() { return; }
    // SAFETY: a non-null free slot has the external DRM object-free signature.
    let free = unsafe { read(funcs.add(DRM_GEM_FUNCS_FREE_OFF).cast::<Option<GemFree>>()) };
    if let Some(free) = free { unsafe { free(object); } }
}

unsafe extern "C" fn shmem_object_free(object: *mut c_void) {
    if object.is_null() { return; }
    // SAFETY: this callback owns the object allocated by drm_gem_shmem_dumb_create and its page-aligned backing.
    let (size, backing) = unsafe { (read(object.cast::<u8>().add(DRM_GEM_SIZE_OFF).cast::<usize>()), read(object.cast::<u8>().add(DRM_GEM_SHMEM_VADDR_OFF).cast::<*mut u8>())) };
    if let Ok(layout) = Layout::from_size_align(size, PAGE_SIZE as usize) { unsafe { dealloc(backing, layout); } }
    let layout = Layout::from_size_align(DRM_GEM_SHMEM_OBJECT_SIZE, core::mem::align_of::<u64>()).unwrap();
    unsafe { dealloc(object.cast(), layout); }
}

unsafe extern "C" fn gem_fb_destroy(fb: *mut c_void) {
    if fb.is_null() { return; }
    // SAFETY: framebuffer is the allocation returned by drm_gem_fb_create_with_dirty; every non-null
    // plane entry owns one lookup reference and must be returned before the framebuffer storage is freed.
    unsafe { for plane in 0..4 { let object = read(fb.cast::<u8>().add(DRM_FB_OBJECTS_OFF + plane * core::mem::size_of::<*mut c_void>()).cast::<*mut c_void>()); if !object.is_null() { object_put(object); } } }
    let layout = Layout::from_size_align(DRM_FB_SIZE, core::mem::align_of::<u64>()).unwrap();
    unsafe { dealloc(fb.cast(), layout); }
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
        for name in ["drm_gem_private_object_init", "drm_gem_object_release", "drm_gem_handle_create", "drm_gem_handle_delete", "drm_gem_object_lookup", "drm_gem_release", "drm_mode_size_dumb", "drm_gem_shmem_dumb_create"] { assert!(crate::symtab::is_exported(name)); }
    }

    #[test]
    fn dumb_size_rounds_pitch_and_size_and_rejects_overflow() {
        let mut args = [0u8; 32];
        // SAFETY: args reserves the complete dumb-buffer ABI record.
        unsafe { write(args.as_mut_ptr().add(DRM_DUMB_HEIGHT_OFF).cast::<u32>(), 768); write(args.as_mut_ptr().add(DRM_DUMB_WIDTH_OFF).cast::<u32>(), 1024); write(args.as_mut_ptr().add(DRM_DUMB_BPP_OFF).cast::<u32>(), 32); }
        assert_eq!(drm_mode_size_dumb(core::ptr::null_mut(), args.as_mut_ptr().cast(), 64, 0), 0);
        // SAFETY: successful sizing populated the checked output fields.
        unsafe { assert_eq!(read(args.as_ptr().add(DRM_DUMB_PITCH_OFF).cast::<u32>()), 4096); assert_eq!(read(args.as_ptr().add(DRM_DUMB_SIZE_OFF).cast::<u64>()), 3_145_728); write(args.as_mut_ptr().add(DRM_DUMB_WIDTH_OFF).cast::<u32>(), u32::MAX); }
        assert_eq!(drm_mode_size_dumb(core::ptr::null_mut(), args.as_mut_ptr().cast(), 0, 0), -LINUX_EINVAL);
    }

    #[test]
    fn shmem_dumb_create_publishes_a_page_backed_handle_and_reclaims_it() {
        let mut file = [0u8; 416]; let mut dev = [0u8; 64]; let mut args = [0u8; 32];
        assert!(file_init(file.as_mut_ptr().cast()));
        // SAFETY: args reserves the complete dumb-buffer ABI record.
        unsafe { write(args.as_mut_ptr().add(DRM_DUMB_HEIGHT_OFF).cast::<u32>(), 4); write(args.as_mut_ptr().add(DRM_DUMB_WIDTH_OFF).cast::<u32>(), 8); write(args.as_mut_ptr().add(DRM_DUMB_BPP_OFF).cast::<u32>(), 32); }
        assert_eq!(drm_gem_shmem_dumb_create(file.as_mut_ptr().cast(), dev.as_mut_ptr().cast(), args.as_mut_ptr().cast()), 0);
        // SAFETY: successful creation populated handle and page-rounded size.
        let handle = unsafe { read(args.as_ptr().add(DRM_DUMB_HANDLE_OFF).cast::<u32>()) }; assert_ne!(handle, 0);
        let object = drm_gem_object_lookup(file.as_mut_ptr().cast(), handle); assert!(!object.is_null());
        // SAFETY: object is live through its file handle and contains the shmem backing pointer.
        unsafe { assert_eq!(read(object.cast::<u8>().add(DRM_GEM_SIZE_OFF).cast::<usize>()), PAGE_SIZE as usize); assert!(!read(object.cast::<u8>().add(DRM_GEM_SHMEM_VADDR_OFF).cast::<*mut u8>()).is_null()); }
        object_put(object);
        assert_eq!(drm_gem_handle_delete(file.as_mut_ptr().cast(), handle), 0); assert!(drm_gem_object_lookup(file.as_mut_ptr().cast(), handle).is_null()); file_release(dev.as_mut_ptr().cast(), file.as_mut_ptr().cast());
    }

    #[test]
    fn gem_framebuffer_keeps_the_backing_object_after_handle_close() {
        let mut file = [0u8; 416]; let mut dev = [0u8; 64]; let mut dumb = [0u8; 32]; let mut cmd = [0u8; 104];
        assert!(file_init(file.as_mut_ptr().cast()));
        // SAFETY: dumb reserves drm_mode_create_dumb and receives one shmem handle.
        unsafe { write(dumb.as_mut_ptr().add(DRM_DUMB_HEIGHT_OFF).cast::<u32>(), 4); write(dumb.as_mut_ptr().add(DRM_DUMB_WIDTH_OFF).cast::<u32>(), 8); write(dumb.as_mut_ptr().add(DRM_DUMB_BPP_OFF).cast::<u32>(), 32); }
        assert_eq!(drm_gem_shmem_dumb_create(file.as_mut_ptr().cast(), dev.as_mut_ptr().cast(), dumb.as_mut_ptr().cast()), 0);
        // SAFETY: cmd reserves drm_mode_fb_cmd2 and is populated with matching dimensions/handle/pitch.
        unsafe { let handle = read(dumb.as_ptr().add(DRM_DUMB_HANDLE_OFF).cast::<u32>()); write(cmd.as_mut_ptr().add(DRM_FB_CMD_WIDTH_OFF).cast::<u32>(), 8); write(cmd.as_mut_ptr().add(DRM_FB_CMD_HEIGHT_OFF).cast::<u32>(), 4); write(cmd.as_mut_ptr().add(DRM_FB_CMD_HANDLES_OFF).cast::<u32>(), handle); write(cmd.as_mut_ptr().add(DRM_FB_CMD_PITCHES_OFF).cast::<u32>(), 32); }
        let info = format::drm_format_info(0x3432_5258).cast::<u8>(); let fb = drm_gem_fb_create_with_dirty(dev.as_mut_ptr().cast(), file.as_mut_ptr().cast(), info, cmd.as_ptr()); assert!(!fb.is_null());
        // SAFETY: successful creation retained the source GEM object in fb->obj[0].
        let object = unsafe { read(fb.cast::<u8>().add(DRM_FB_OBJECTS_OFF).cast::<*mut c_void>()) }; let handle = unsafe { read(dumb.as_ptr().add(DRM_DUMB_HANDLE_OFF).cast::<u32>()) };
        assert_eq!(drm_gem_handle_delete(file.as_mut_ptr().cast(), handle), 0); assert!(!object.is_null());
        unsafe { gem_fb_destroy(fb); } file_release(dev.as_mut_ptr().cast(), file.as_mut_ptr().cast());
    }
}
