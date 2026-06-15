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
}
