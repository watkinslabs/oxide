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
