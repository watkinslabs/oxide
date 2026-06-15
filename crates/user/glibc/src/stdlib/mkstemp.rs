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

// # C: int mkstemp(char *template)
#[no_mangle]
pub unsafe extern "C" fn mkstemp(template: *mut u8) -> i32 {
    // SAFETY: template is a writable C string ending in "XXXXXX"; we overwrite
    // those 6 bytes in place and openat the result.
    unsafe {
        let n = strlen_impl(template);
        if n < 6 { errno::set(EINVAL); return -1; }
        let xs = template.add(n - 6);
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
            let fd = sys4(nr::OPENAT, AT_FDCWD, template as usize, O_RDWR | O_CREAT | O_EXCL, 0o600) as i32;
            if fd >= 0 { return fd; }
            if fd != -EEXIST { errno::set(-fd); return -1; } // a non-collision error
            r = r.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); // LCG step
        }
        errno::set(EEXIST);
        -1
    }
}
