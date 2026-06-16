//! dlfcn — dlopen/dlsym/dlclose/dladdr (docs/59§3, §6 G12). In glibc 2.34+
//! libdl is folded into libc.so.6; these are thin wrappers over the dynamic
//! linker's `_dl_*` entry points, which libc.so.6 references as undefined and
//! the rtld (ld.so, in the link scope) resolves at load time. Static builds
//! that never call dlopen drop these (unreferenced), so the externs don't
//! break a static link.
#![allow(clippy::upper_case_acronyms)]
#[cfg(feature = "freestanding")]
pub use api::*;

pub const RTLD_LAZY: i32 = 1;
pub const RTLD_NOW: i32 = 2;
pub const RTLD_GLOBAL: i32 = 0x100;
pub const RTLD_LOCAL: i32 = 0;

#[cfg(feature = "freestanding")]
mod api {
    use core::ffi::c_void;

    extern "C" {
        fn _dl_open(path: *const u8, mode: i32) -> usize;
        fn _dl_sym(handle: usize, name: *const u8) -> usize;
        fn _dl_close(handle: usize) -> i32;
        fn _dl_addr(addr: usize, fbase_out: *mut usize) -> i32;
        fn _dl_iterate_phdr(cb: extern "C" fn(*const c_void, usize, *mut c_void) -> i32, data: *mut c_void) -> i32;
    }

    // # C: int dl_iterate_phdr(int (*cb)(struct dl_phdr_info*, size_t, void*), void *data)
    #[no_mangle]
    pub unsafe extern "C" fn dl_iterate_phdr(cb: extern "C" fn(*const c_void, usize, *mut c_void) -> i32, data: *mut c_void) -> i32 {
        // SAFETY: delegates to the rtld, which walks its link map and calls cb
        // once per loaded object with a struct dl_phdr_info.
        unsafe { _dl_iterate_phdr(cb, data) }
    }

    // # C: void *dlopen(const char *file, int mode)
    #[no_mangle]
    pub unsafe extern "C" fn dlopen(file: *const u8, mode: i32) -> *mut c_void {
        // SAFETY: file is NUL-terminated or null; delegates to the rtld loader.
        unsafe { _dl_open(file, mode) as *mut c_void }
    }

    // # C: void *dlsym(void *handle, const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn dlsym(handle: *mut c_void, name: *const u8) -> *mut c_void {
        // SAFETY: handle is a dlopen result or RTLD_DEFAULT(null); name NUL-term.
        unsafe { _dl_sym(handle as usize, name) as *mut c_void }
    }

    // # C: int dlclose(void *handle)
    #[no_mangle]
    pub unsafe extern "C" fn dlclose(handle: *mut c_void) -> i32 {
        // SAFETY: handle is a dlopen result; the rtld decrefs (unmap is later).
        unsafe { _dl_close(handle as usize) }
    }

    // # C: char *dlerror(void) — no sticky error tracking yet (NULL).
    #[no_mangle]
    pub extern "C" fn dlerror() -> *mut u8 { core::ptr::null_mut() }

    #[repr(C)]
    pub struct Dl_info {
        pub dli_fname: *const u8,
        pub dli_fbase: *mut c_void,
        pub dli_sname: *const u8,
        pub dli_saddr: *mut c_void,
    }

    // # C: int dladdr(const void *addr, Dl_info *info)
    #[no_mangle]
    pub unsafe extern "C" fn dladdr(addr: *const c_void, info: *mut Dl_info) -> i32 {
        // SAFETY: info is a writable Dl_info; the rtld fills the containing
        // object's base (sname/saddr are a follow-up).
        unsafe {
            if info.is_null() { return 0; }
            let mut fbase = 0usize;
            let r = _dl_addr(addr as usize, &mut fbase);
            (*info).dli_fname = core::ptr::null();
            (*info).dli_fbase = fbase as *mut c_void;
            (*info).dli_sname = core::ptr::null();
            (*info).dli_saddr = core::ptr::null_mut();
            r
        }
    }

    // # C: void *dlvsym(void *handle, const char *name, const char *version)
    // We resolve unversioned (the rtld matches the default version); the
    // explicit `version` is advisory here.
    #[no_mangle]
    pub unsafe extern "C" fn dlvsym(handle: *mut c_void, name: *const u8, _version: *const u8) -> *mut c_void {
        // SAFETY: handle is a dlopen result or RTLD_DEFAULT(null); name NUL-term.
        unsafe { _dl_sym(handle as usize, name) as *mut c_void }
    }

    // # C: int dladdr1(const void *addr, Dl_info *info, void **extra, int flags)
    // dladdr + an extra out-param (RTLD_DL_SYMENT/RTLD_DL_LINKMAP); we fill the
    // Dl_info and clear *extra (symbol-entry/link-map detail is a follow-up).
    #[no_mangle]
    pub unsafe extern "C" fn dladdr1(addr: *const c_void, info: *mut Dl_info, extra: *mut *mut c_void, flags: i32) -> i32 {
        // SAFETY: info writable Dl_info; extra null or a writable void* out-param.
        // glibc only writes *extra for RTLD_DL_SYMENT(1)/RTLD_DL_LINKMAP(2);
        // flags 0 leaves it untouched. We have no sym-entry/link-map detail yet
        // → NULL for those requests.
        unsafe {
            if (flags == 1 || flags == 2) && !extra.is_null() { *extra = core::ptr::null_mut(); }
            dladdr(addr, info)
        }
    }

    // # C: void *dlmopen(Lmid_t lmid, const char *file, int mode)
    // Single link-map namespace: LM_ID_BASE/LM_ID_NEWLM both load into it.
    #[no_mangle]
    pub unsafe extern "C" fn dlmopen(_lmid: isize, file: *const u8, mode: i32) -> *mut c_void {
        // SAFETY: file NUL-terminated or null; delegates to the one-namespace loader.
        unsafe { _dl_open(file, mode) as *mut c_void }
    }

    // # C: int dlinfo(void *handle, int request, void *arg)
    // RTLD_DI_LINKMAP(2): *arg = handle (our handle IS the link-map node).
    // Other requests are not yet supported → -1.
    #[no_mangle]
    pub unsafe extern "C" fn dlinfo(handle: *mut c_void, request: i32, arg: *mut c_void) -> i32 {
        // SAFETY: arg is request-specific; for RTLD_DI_LINKMAP it is a void** we set.
        unsafe {
            if request == 2 && !arg.is_null() { *(arg as *mut *mut c_void) = handle; 0 } else { -1 }
        }
    }
}
