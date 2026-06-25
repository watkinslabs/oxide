// program_invocation_name / program_invocation_short_name (GNU, errno.h).
// glibc exposes two writable `char *` data symbols: the full argv[0] and
// its basename. err()/warn()/error() prefix their diagnostics with the
// short name. __libc_start_main calls seed(argv0) once at startup.

use core::cell::UnsafeCell;
use core::ptr;

#[repr(transparent)]
struct CharP(UnsafeCell<*mut u8>);
// SAFETY: written once by seed() at single-threaded startup before any
// thread is created; thereafter read-only unless the program assigns the
// public data symbol itself, which is the documented glibc contract.
unsafe impl Sync for CharP {}

// # C: char *program_invocation_name;  (full argv[0])
#[cfg(feature = "freestanding")]
#[no_mangle]
static program_invocation_name: CharP = CharP(UnsafeCell::new(ptr::null_mut()));

// # C: char *program_invocation_short_name;  (basename of argv[0])
#[cfg(feature = "freestanding")]
#[no_mangle]
static program_invocation_short_name: CharP = CharP(UnsafeCell::new(ptr::null_mut()));

#[cfg(feature = "freestanding")]
core::arch::global_asm!(
    ".globl __progname",
    ".set __progname, program_invocation_short_name",
    ".globl __progname_full",
    ".set __progname_full, program_invocation_name",
);

/// # C: const char *the short program name, "" if argv[0] was NULL.
pub(crate) fn short() -> *const u8 {
    #[cfg(feature = "freestanding")]
    // SAFETY: plain pointer load of the startup-seeded short-name slot.
    let p = unsafe { *program_invocation_short_name.0.get() };
    #[cfg(not(feature = "freestanding"))]
    let p: *mut u8 = ptr::null_mut();
    if p.is_null() { c"".as_ptr() as *const u8 } else { p }
}

/// # C: const char *the full argv[0] program name, "" if it was NULL.
pub(crate) fn full() -> *const u8 {
    #[cfg(feature = "freestanding")]
    // SAFETY: plain pointer load of the startup-seeded full-name slot.
    let p = unsafe { *program_invocation_name.0.get() };
    #[cfg(not(feature = "freestanding"))]
    let p: *mut u8 = ptr::null_mut();
    if p.is_null() { c"".as_ptr() as *const u8 } else { p }
}

// # C: seed program_invocation_name + _short_name from argv[0] (startup).
#[cfg(feature = "freestanding")]
pub(crate) unsafe fn seed(argv0: *mut u8) {
    if argv0.is_null() { return; }
    // SAFETY: argv0 is the kernel-provided NUL-terminated argv[0] string;
    // scan to the final '/' to find the basename, both stay inside it.
    unsafe {
        *program_invocation_name.0.get() = argv0;
        let len = crate::string::len::strlen_impl(argv0);
        let mut base = argv0;
        let mut i = 0usize;
        while i < len { if *argv0.add(i) == b'/' { base = argv0.add(i + 1); } i += 1; }
        *program_invocation_short_name.0.get() = base;
    }
}
