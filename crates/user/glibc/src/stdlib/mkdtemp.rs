// mkdtemp(3) + mktemp(3) (docs/59§6 G7). Replace the trailing "XXXXXX" of
// `template` with base-62 letters drawn from getrandom(2). mkdtemp loops
// mkdir(0700) until it wins a unique name and returns the template; mktemp
// (deprecated) fills the template with a name that currently does not exist
// (faccessat F_OK). Name generation and the retry loop live in
// `super::tempname` (glibc sysdeps/posix/tempname.c `try_tempname_len`),
// shared with mkstemp. C ABI.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::sys3;
use crate::internal::nr;
use crate::stdlib::tempname::gen::{try_tempname, EEXIST};

const AT_FDCWD: usize = (-100i64) as usize;
const F_OK: usize = 0;
// glibc try_dir(): S_IRUSR|S_IWUSR|S_IXUSR.
const TEMPDIR_MODE: usize = 0o700;

// # C: char *mkdtemp(char *template)
#[no_mangle]
pub unsafe extern "C" fn mkdtemp(template: *mut u8) -> *mut u8 {
    let try_dir = |t: *mut u8| {
        // SAFETY: mkdirat(2) on the freshly rewritten template, a NUL-terminated
        // path owned by the caller; directory creation is atomic in the kernel.
        unsafe { sys3(nr::MKDIRAT, AT_FDCWD, t as usize, TEMPDIR_MODE) }
    };
    // SAFETY: template is a writable C string ending in "XXXXXX"; try_tempname
    // validates that run, rewrites it, and mkdirat's until a name wins.
    let rc = unsafe { try_tempname(template, 0, try_dir) };
    if rc < 0 { core::ptr::null_mut() } else { template }
}

// # C: char *mktemp(char *template) — deprecated; pick an unused name.
#[no_mangle]
pub unsafe extern "C" fn mktemp(template: *mut u8) -> *mut u8 {
    // glibc try_nocreate(): name exists → EEXIST, ENOENT → accept.
    let try_nocreate = |t: *mut u8| {
        // SAFETY: faccessat(2) on the freshly rewritten template, a
        // NUL-terminated path owned by the caller; the probe writes nothing.
        if unsafe { sys3(nr::FACCESSAT, AT_FDCWD, t as usize, F_OK) } < 0 { 0 } else { -(EEXIST as isize) }
    };
    // SAFETY: template is a writable C string ending in "XXXXXX"; try_tempname
    // rewrites that run until faccessat(F_OK) reports the name nonexistent, and
    // on exhaustion we truncate the same writable buffer to the empty string.
    unsafe {
        let rc = try_tempname(template, 0, try_nocreate);
        // Exhausted / invalid template: empty string per the mktemp contract.
        if rc < 0 { *template = 0; }
        template
    }
}

// # C: char *__mktemp(char *template)
#[no_mangle]
pub unsafe extern "C" fn __mktemp(template: *mut u8) -> *mut u8 {
    // SAFETY: internal alias has the same writable-template contract as mktemp.
    unsafe { mktemp(template) }
}
