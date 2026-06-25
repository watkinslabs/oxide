// mkdtemp(3) + mktemp(3) (docs/59§6 G7). Replace the trailing "XXXXXX" of
// `template` with random alphanumerics. mkdtemp loops mkdir(0700) until it
// wins a unique name and returns the template; mktemp (deprecated) fills the
// template with a name that currently does not exist (faccessat F_OK). Entropy
// mirrors mkstemp: clock_gettime mixed with a process-global sequence. C ABI.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::sys3;
use crate::internal::{errno, nr};
use crate::string::len::strlen_impl;
use crate::time::clock::{clock_gettime, timespec, CLOCK_REALTIME};
use core::sync::atomic::{AtomicU64, Ordering};

const AT_FDCWD: usize = (-100i64) as usize;
const F_OK: usize = 0;
const EINVAL: i32 = 22;
const EEXIST: i32 = 17;
const TABLE: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static SEQ: AtomicU64 = AtomicU64::new(0x5DEC_E66D);

// Seed a 64-bit RNG state from the clock + a process-global sequence.
fn seed() -> u64 {
    let mut ts = timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime writes a valid local timespec out-param.
    unsafe { clock_gettime(CLOCK_REALTIME, &mut ts); }
    (ts.tv_nsec as u64).rotate_left(17)
        ^ (ts.tv_sec as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ SEQ.fetch_add(0x1000_0001, Ordering::Relaxed)
}

// Validate the template's trailing "XXXXXX". Returns the XXXXXX start pointer.
// SAFETY contract: caller guarantees `template` is a writable C string.
unsafe fn xs_of(template: *mut u8) -> Option<*mut u8> {
    // SAFETY: caller guarantees template is a writable NUL-terminated string;
    // we measure it and require ≥6 trailing 'X' bytes to overwrite.
    unsafe {
        let n = strlen_impl(template);
        if n < 6 { return None; }
        let xs = template.add(n - 6);
        for k in 0..6 { if *xs.add(k) != b'X' { return None; } }
        Some(xs)
    }
}

// # C: char *mkdtemp(char *template)
#[no_mangle]
pub unsafe extern "C" fn mkdtemp(template: *mut u8) -> *mut u8 {
    // SAFETY: template is a writable C string ending in "XXXXXX"; we overwrite
    // those 6 bytes in place and mkdirat the result until a unique name wins.
    unsafe {
        let xs = match xs_of(template) { Some(p) => p, None => { errno::set(EINVAL); return core::ptr::null_mut(); } };
        let mut r = seed();
        for _ in 0..0x40000 {
            let mut x = r;
            for k in 0..6 { *xs.add(k) = TABLE[(x % 62) as usize]; x /= 62; }
            let rc = sys3(nr::MKDIRAT, AT_FDCWD, template as usize, 0o700) as i32;
            if rc == 0 { return template; }
            if rc != -EEXIST { errno::set(-rc); return core::ptr::null_mut(); }
            r = r.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        }
        errno::set(EEXIST);
        core::ptr::null_mut()
    }
}

// # C: char *mktemp(char *template) — deprecated; pick an unused name.
#[no_mangle]
pub unsafe extern "C" fn mktemp(template: *mut u8) -> *mut u8 {
    // SAFETY: template is a writable C string ending in "XXXXXX"; we overwrite
    // those 6 bytes with a name that faccessat(F_OK) reports as nonexistent.
    unsafe {
        let xs = match xs_of(template) { Some(p) => p, None => { errno::set(EINVAL); *template = 0; return template; } };
        let mut r = seed();
        for _ in 0..0x40000 {
            let mut x = r;
            for k in 0..6 { *xs.add(k) = TABLE[(x % 62) as usize]; x /= 62; }
            // faccessat(AT_FDCWD, template, F_OK) < 0 → does not exist → use it.
            if sys3(nr::FACCESSAT, AT_FDCWD, template as usize, F_OK) < 0 { return template; }
            r = r.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        }
        *template = 0; // exhausted: empty string per mktemp contract
        template
    }
}

// # C: char *__mktemp(char *template)
#[no_mangle]
pub unsafe extern "C" fn __mktemp(template: *mut u8) -> *mut u8 {
    // SAFETY: internal alias has the same writable-template contract as mktemp.
    unsafe { mktemp(template) }
}
