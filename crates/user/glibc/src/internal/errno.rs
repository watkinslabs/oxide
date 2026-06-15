// errno — exposed to C via `__errno_location` (docs/59§2, §6 G12f).
// Per-thread: errno lives in the thread's TCB (pthread::Tcb::errno), reached
// via the thread pointer (fs:0 / tpidr_el0). A process-wide cell is the
// fallback before the main-thread TCB is installed and for hosted tests. A
// syscall returning -4095..=-1 is `-errno` (Linux ABI); `ret` splits ok/err,
// `ret_isize` applies the libc convention (return -1, set errno).
use core::cell::UnsafeCell;

struct ErrnoCell(UnsafeCell<i32>);
// SAFETY: the global cell is only the pre-TCB/hosted fallback; once a TCB is
// installed each thread uses its own TCB slot, so no cross-thread aliasing.
unsafe impl Sync for ErrnoCell {}
static ERRNO: ErrnoCell = ErrnoCell(UnsafeCell::new(0));

// # C: int *__errno_location(void) — address of the thread's errno.
#[cfg(feature = "freestanding")]
#[no_mangle]
pub extern "C" fn __errno_location() -> *mut i32 {
    // SAFETY: current_tcb reads the thread pointer; once init_main_tcb /
    // pthread_create has run (before any errno access) it is a live TCB. The
    // null check covers the brief pre-TCB startup window.
    unsafe {
        let tcb = crate::pthread::current_tcb();
        if tcb.is_null() { ERRNO.0.get() } else { core::ptr::addr_of_mut!((*tcb).errno) }
    }
}

/// # C: *__errno_location() = e
pub(crate) fn set(e: i32) {
    #[cfg(feature = "freestanding")]
    // SAFETY: __errno_location returns this thread's errno slot (TCB or the
    // startup fallback); writing through it is the libc errno contract.
    unsafe { *__errno_location() = e };
    #[cfg(not(feature = "freestanding"))]
    // SAFETY: hosted/test build uses the single global cell, single-threaded.
    unsafe { *ERRNO.0.get() = e };
}

/// # C: split raw return: -errno band → Err, else Ok
#[inline]
pub(crate) fn ret(r: isize) -> Result<isize, i32> {
    if (-4095..=-1).contains(&r) { Err(-r as i32) } else { Ok(r) }
}

/// # C: on error set errno + return -1, else pass value
#[inline]
pub(crate) fn ret_isize(r: isize) -> isize {
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
