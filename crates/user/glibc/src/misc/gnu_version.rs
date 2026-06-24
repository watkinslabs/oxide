// GNU libc implementation identity (<gnu/libc-version.h>).
// The version string reflects the highest GLIBC_* node this libc advertises in
// its version scripts, not the host used to build/test it.

// # C: const char *gnu_get_libc_version(void)
#[no_mangle]
pub extern "C" fn gnu_get_libc_version() -> *const u8 {
    b"2.38\0".as_ptr()
}

// # C: const char *gnu_get_libc_release(void)
#[no_mangle]
pub extern "C" fn gnu_get_libc_release() -> *const u8 {
    b"stable\0".as_ptr()
}
