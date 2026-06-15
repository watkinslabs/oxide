// rt/clock_extra — clock_settime (docs/59§6 G17b). Thin syscall shim over the
// existing time::clock timespec (clock_nanosleep already lives in time::clock).
#![cfg(feature = "freestanding")]
use crate::arch::syscall::sys2;
use crate::internal::errno::ret_isize;
use crate::internal::nr;
use crate::time::clock::timespec;

// # C: int clock_settime(clockid_t clk, const struct timespec *ts)
#[no_mangle]
pub unsafe extern "C" fn clock_settime(clk: i32, ts: *const timespec) -> i32 {
    // SAFETY: ts is a valid timespec; returns 0 / -1 with errno set.
    ret_isize(unsafe { sys2(nr::CLOCK_SETTIME, clk as usize, ts as usize) }) as i32
}
