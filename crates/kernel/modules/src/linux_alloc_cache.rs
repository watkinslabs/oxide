// Linux slab-cache KPI helpers owned by linux_alloc.rs.

use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr::null_mut;

use super::{alloc_bytes, free_bytes, LinuxKmemCache, CACHE_MAGIC, GFP_ZERO, MIN_ALIGN};

#[repr(C)]
pub struct LinuxKmemCacheArgs {
    pub(crate) align: u32,
    pub(crate) useroffset: u32,
    pub(crate) usersize: u32,
    pub(crate) freeptr_offset: u32,
    pub(crate) use_freeptr_offset: bool,
    pub(crate) ctor: Option<unsafe extern "C" fn(*mut c_void)>,
}

pub(super) unsafe extern "C" fn __kmem_cache_create_args(
    _name: *const u8,
    object_size: u32,
    args: *const LinuxKmemCacheArgs,
    _flags: u32,
) -> *mut LinuxKmemCache {
    let align = if args.is_null() {
        MIN_ALIGN
    } else {
        // SAFETY: args follows Linux struct kmem_cache_args layout for this ABI.
        unsafe { (*args).align as usize }.max(MIN_ALIGN)
    };
    let ctor = if args.is_null() {
        None
    } else {
        // SAFETY: args follows Linux struct kmem_cache_args layout for this ABI.
        unsafe { (*args).ctor }
    };
    if object_size == 0 { return null_mut(); }
    Box::into_raw(Box::new(LinuxKmemCache {
        magic: CACHE_MAGIC,
        object_size: object_size as usize,
        align,
        ctor,
    }))
}

pub(super) extern "C" fn kmem_cache_alloc_noprof(cache: *mut LinuxKmemCache, flags: u32) -> *mut u8 {
    if !valid_cache(cache) { return null_mut(); }
    // SAFETY: valid_cache accepted the metadata pointer.
    let (size, align, ctor) = unsafe { ((*cache).object_size, (*cache).align, (*cache).ctor) };
    let p = alloc_bytes(size, align, flags & GFP_ZERO != 0);
    if !p.is_null() {
        if let Some(ctor) = ctor {
            // SAFETY: ctor is the cache constructor registered by the module for this object type.
            unsafe { ctor(p as *mut c_void); }
        }
    }
    p
}

pub(super) extern "C" fn kmem_cache_free(cache: *mut LinuxKmemCache, obj: *mut c_void) {
    if valid_cache(cache) {
        // SAFETY: kmem_cache_free requires obj to be a live allocation from cache's allocation surface.
        unsafe { free_bytes(obj as *mut u8); }
    }
}

pub(super) extern "C" fn kmem_cache_destroy(cache: *mut LinuxKmemCache) {
    if !valid_cache(cache) { return; }
    // SAFETY: cache was allocated by Box::into_raw in __kmem_cache_create_args.
    unsafe { drop(Box::from_raw(cache)); }
}

fn valid_cache(cache: *mut LinuxKmemCache) -> bool {
    if cache.is_null() { return false; }
    // SAFETY: caller passes an opaque kmem_cache pointer; bad magic is rejected.
    unsafe { (*cache).magic == CACHE_MAGIC }
}
