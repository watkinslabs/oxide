// Kernel entropy (docs/59§6 G8): getrandom(2) wrapper + getentropy(3) which
// loops getrandom to fill the buffer fully (GRND_NONBLOCK off) and rejects
// lengths >256 with EIO, matching glibc. Both arches share the slot.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::sys3;
use crate::internal::errno::{ret, ret_isize, set};
use crate::internal::nr;

const EIO: i32 = 5;
const EINTR: i32 = 4;
const GETENTROPY_MAX: usize = 256;

// getrandom(2) flags.
pub const GRND_NONBLOCK: u32 = 0x0001;
pub const GRND_RANDOM: u32 = 0x0002;
pub const GRND_INSECURE: u32 = 0x0004;

// # C: ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)
#[no_mangle]
pub unsafe extern "C" fn getrandom(buf: *mut u8, buflen: usize, flags: u32) -> isize {
    // SAFETY: getrandom(2); the kernel writes up to buflen bytes into buf and
    // validates the range, faulting on a bad pointer rather than corrupting libc.
    ret_isize(unsafe { sys3(nr::GETRANDOM, buf as usize, buflen, flags as usize) })
}

// # C: void arc4random_buf(void *buf, size_t n) — fill n bytes with CSPRNG bytes.
#[no_mangle]
pub unsafe extern "C" fn arc4random_buf(buf: *mut core::ffi::c_void, n: usize) {
    // SAFETY: loop getrandom until n bytes are written (arc4random never fails);
    // the kernel validates each shrinking range.
    unsafe {
        let p = buf as *mut u8;
        let mut done = 0usize;
        while done < n {
            let r = sys3(nr::GETRANDOM, p.add(done) as usize, n - done, 0);
            match ret(r) {
                Ok(k) if k > 0 => done += k as usize,
                Err(e) if e == EINTR => continue,
                _ => { core::ptr::write_bytes(p.add(done), 0, n - done); break; }
            }
        }
    }
}
// # C: uint32_t arc4random(void)
#[no_mangle]
pub unsafe extern "C" fn arc4random() -> u32 {
    // SAFETY: fill a 4-byte stack word with CSPRNG bytes.
    unsafe { let mut v: u32 = 0; arc4random_buf(&mut v as *mut u32 as *mut core::ffi::c_void, 4); v }
}
// # C: uint32_t arc4random_uniform(uint32_t upper_bound) — unbiased [0,upper).
#[no_mangle]
pub unsafe extern "C" fn arc4random_uniform(upper: u32) -> u32 {
    if upper < 2 { return 0; }
    // Rejection sampling: discard the low (2^32 % upper) values to avoid modulo bias.
    let min = upper.wrapping_neg() % upper;
    // SAFETY: arc4random reads kernel entropy; loop until an unbiased draw.
    unsafe { loop { let r = arc4random(); if r >= min { return r % upper; } } }
}

// # C: int getentropy(void *buf, size_t buflen) — 0 / -1+errno, max 256 bytes.
#[no_mangle]
pub unsafe extern "C" fn getentropy(buf: *mut u8, buflen: usize) -> i32 {
    if buflen > GETENTROPY_MAX { set(EIO); return -1; }
    // SAFETY: loop getrandom over the same buffer until full; the kernel writes
    // each chunk into buf+done and validates the (shrinking) range each call.
    unsafe {
        let mut done = 0usize;
        while done < buflen {
            let r = sys3(nr::GETRANDOM, buf.add(done) as usize, buflen - done, 0);
            match ret(r) {
                Ok(n) if n > 0 => done += n as usize,
                Ok(_) => { set(EIO); return -1; }
                Err(e) if e == EINTR => continue,
                Err(_) => { set(EIO); return -1; }
            }
        }
    }
    0
}
