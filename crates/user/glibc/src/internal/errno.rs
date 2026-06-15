// errno — exposed to C via `__errno_location` (docs/59§2). One
// process-wide cell until TLS lands (G11), at which point this becomes a
// per-thread slot. A syscall returning -4095..=-1 is `-errno` (Linux
// ABI); `ret` splits ok/err, `ret_isize` applies the libc convention
// (return -1, set errno).
use core::cell::UnsafeCell;

struct ErrnoCell(UnsafeCell<i32>);
// SAFETY: single-threaded until G11 wires real TLS; the cell is only
// touched through set()/__errno_location on the one running thread.
unsafe impl Sync for ErrnoCell {}
static ERRNO: ErrnoCell = ErrnoCell(UnsafeCell::new(0));

// # C: int *__errno_location(void) — address of the thread's errno.
#[cfg(feature = "freestanding")]
#[no_mangle]
pub extern "C" fn __errno_location() -> *mut i32 {
    ERRNO.0.get()
}

pub fn set(e: i32) {
    // SAFETY: exclusive single-thread access to the global errno cell
    // until per-thread TLS replaces it at G11; no aliasing &mut exists.
    unsafe { *ERRNO.0.get() = e };
}

// Split a raw syscall return: Err(errno) in the [-4095,-1] band, else Ok.
#[inline]
pub fn ret(r: isize) -> Result<isize, i32> {
    if (-4095..=-1).contains(&r) { Err(-r as i32) } else { Ok(r) }
}

// libc convention: on error set errno and return -1, else pass the value.
#[inline]
pub fn ret_isize(r: isize) -> isize {
    match ret(r) {
        Ok(v) => v,
        Err(e) => { set(e); -1 }
    }
}

#[cfg(test)]
mod tests {
    use super::{ret, ret_isize, set, ERRNO};
    #[test]
    fn errno_band_splits() {
        assert_eq!(ret(-1), Err(1));
        assert_eq!(ret(-4095), Err(4095));
        assert_eq!(ret(0), Ok(0));
        assert_eq!(ret(42), Ok(42));
        assert_eq!(ret(-4096), Ok(-4096)); // below band = valid (e.g. mmap addr)
    }
    #[test]
    fn ret_isize_sets_errno() {
        set(0);
        assert_eq!(ret_isize(-2), -1);
        // SAFETY: test is single-threaded; read the cell we just set.
        assert_eq!(unsafe { *ERRNO.0.get() }, 2);
        assert_eq!(ret_isize(7), 7);
    }
}
