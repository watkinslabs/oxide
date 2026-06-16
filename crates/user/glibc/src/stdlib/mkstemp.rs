// mkstemp(3) (docs/59§6 G7). Replace the trailing "XXXXXX" of `template` with
// random alphanumerics and open(O_RDWR|O_CREAT|O_EXCL, 0600), retrying on a
// collision. Entropy from clock_gettime + a process-global sequence (glibc
// mixes time/pid similarly). C ABI only.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::sys4;
use crate::internal::{errno, nr};
use crate::string::len::strlen_impl;
use crate::time::clock::{clock_gettime, timespec, CLOCK_REALTIME};
use core::sync::atomic::{AtomicU64, Ordering};

const AT_FDCWD: usize = (-100i64) as usize;
const O_RDWR: usize = 2;
const O_CREAT: usize = 0o100;
const O_EXCL: usize = 0o200;
const EINVAL: i32 = 22;
const EEXIST: i32 = 17;
const TABLE: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static SEQ: AtomicU64 = AtomicU64::new(0);

// Core: fill the trailing "XXXXXX" + suffixlen bytes before it, openat with
// O_RDWR|O_CREAT|O_EXCL | extra. suffixlen = chars after "XXXXXX" (mkstemps).
unsafe fn do_mkstemp(template: *mut u8, extra: usize, suffixlen: usize) -> i32 {
    // SAFETY: template is a writable C string with "XXXXXX" suffixlen bytes from
    // the end; we overwrite those 6 bytes in place and openat the result.
    unsafe {
        let n = strlen_impl(template);
        if n < 6 + suffixlen { errno::set(EINVAL); return -1; }
        let xs = template.add(n - 6 - suffixlen);
        for k in 0..6 { if *xs.add(k) != b'X' { errno::set(EINVAL); return -1; } }

        let mut ts = timespec { tv_sec: 0, tv_nsec: 0 };
        clock_gettime(CLOCK_REALTIME, &mut ts);
        let mut r = (ts.tv_nsec as u64)
            .rotate_left(17)
            ^ (ts.tv_sec as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ SEQ.fetch_add(0x1000_0001, Ordering::Relaxed);

        for _ in 0..0x40000 {
            let mut x = r;
            for k in 0..6 { *xs.add(k) = TABLE[(x % 62) as usize]; x /= 62; }
            let fd = sys4(nr::OPENAT, AT_FDCWD, template as usize, O_RDWR | O_CREAT | O_EXCL | extra, 0o600) as i32;
            if fd >= 0 { return fd; }
            if fd != -EEXIST { errno::set(-fd); return -1; } // a non-collision error
            r = r.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); // LCG step
        }
        errno::set(EEXIST);
        -1
    }
}

// # C: int mkstemp(char *template)
#[no_mangle]
pub unsafe extern "C" fn mkstemp(template: *mut u8) -> i32 {
    // SAFETY: template ends in "XXXXXX"; do_mkstemp overwrites them + opens.
    unsafe { do_mkstemp(template, 0, 0) }
}

// # C: int mkostemp(char *template, int flags) — mkstemp + extra open flags.
#[no_mangle]
pub unsafe extern "C" fn mkostemp(template: *mut u8, flags: i32) -> i32 {
    // glibc masks out O_RDWR/O_CREAT/O_EXCL/O_ACCMODE from the caller flags (it
    // always sets those), passing the rest (O_CLOEXEC etc.) through to openat.
    let extra = (flags as usize) & !(O_RDWR | O_CREAT | O_EXCL | 0o3);
    // SAFETY: template ends in "XXXXXX"; do_mkstemp overwrites them + opens with
    // the extra (masked) flags OR'd into the openat call.
    unsafe { do_mkstemp(template, extra, 0) }
}

// # C: int mkstemps(char *template, int suffixlen) — "XXXXXX<suffix>".
#[no_mangle]
pub unsafe extern "C" fn mkstemps(template: *mut u8, suffixlen: i32) -> i32 {
    // SAFETY: as mkstemp with a fixed suffix after the X's.
    unsafe { do_mkstemp(template, 0, suffixlen.max(0) as usize) }
}

// # C: int mkostemps(char *template, int suffixlen, int flags) — mkstemps + flags.
#[no_mangle]
pub unsafe extern "C" fn mkostemps(template: *mut u8, suffixlen: i32, flags: i32) -> i32 {
    let extra = (flags as usize) & !(O_RDWR | O_CREAT | O_EXCL | 0o3);
    // SAFETY: "XXXXXX<suffix>"; do_mkstemp overwrites the X's + opens with the
    // extra (masked) flags.
    unsafe { do_mkstemp(template, extra, suffixlen.max(0) as usize) }
}

// LFS aliases — identical on LP64 (off64_t == off_t; the temp path is the same).
// SAFETY: mkstemp64 == mkstemp on LP64; template ends in the "XXXXXX" run.
#[no_mangle] pub unsafe extern "C" fn mkstemp64(t: *mut u8) -> i32 { unsafe { mkstemp(t) } }
// SAFETY: mkstemps64 == mkstemps on LP64; "XXXXXX<suffix>" template.
#[no_mangle] pub unsafe extern "C" fn mkstemps64(t: *mut u8, s: i32) -> i32 { unsafe { mkstemps(t, s) } }
// SAFETY: mkostemp64 == mkostemp on LP64; template + extra open flags.
#[no_mangle] pub unsafe extern "C" fn mkostemp64(t: *mut u8, f: i32) -> i32 { unsafe { mkostemp(t, f) } }
// SAFETY: mkostemps64 == mkostemps on LP64; suffix + extra open flags.
#[no_mangle] pub unsafe extern "C" fn mkostemps64(t: *mut u8, s: i32, f: i32) -> i32 { unsafe { mkostemps(t, s, f) } }
