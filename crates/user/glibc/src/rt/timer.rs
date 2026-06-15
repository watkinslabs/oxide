// rt/timer — POSIX per-process timers (docs/59§6 G17b). Thin shims over the
// timer_* syscalls; structs are ABI-verified vs the libc crate. The kernel
// timer id (an int) is carried in the pointer-sized timer_t.
use super::Timespec;

#[repr(C)]
pub struct itimerspec { pub it_interval: Timespec, pub it_value: Timespec }

#[repr(C)]
pub struct sigevent {
    pub sigev_value: usize, // union sigval (int/ptr)
    pub sigev_signo: i32,
    pub sigev_notify: i32,
    _pad: [u8; 64 - 16], // glibc __SIGEV_MAX_SIZE remainder
}
const _: () = assert!(core::mem::size_of::<sigevent>() == 64);

#[cfg(feature = "freestanding")]
pub use imp::*;

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use core::ffi::c_void;
    use crate::arch::syscall::{sys1, sys3, sys4};
    use crate::internal::errno::ret_isize;
    use crate::internal::nr;

    // # C: int timer_create(clockid_t clk, struct sigevent *sevp, timer_t *timerid)
    #[no_mangle]
    pub unsafe extern "C" fn timer_create(clk: i32, sevp: *mut sigevent, timerid: *mut *mut c_void) -> i32 {
        // SAFETY: sevp is null or a valid sigevent; timerid is writable. The
        // syscall writes a kernel timer id (int); store it pointer-encoded.
        unsafe {
            let mut kid: i32 = 0;
            let r = ret_isize(sys3(nr::TIMER_CREATE, clk as usize, sevp as usize, &mut kid as *mut i32 as usize));
            if r < 0 { return -1; }
            *timerid = kid as usize as *mut c_void;
            0
        }
    }

    // # C: int timer_settime(timer_t timerid, int flags, const struct itimerspec *new, struct itimerspec *old)
    #[no_mangle]
    pub unsafe extern "C" fn timer_settime(timerid: *mut c_void, flags: i32, new: *const itimerspec, old: *mut itimerspec) -> i32 {
        // SAFETY: timerid carries the kernel timer id; new valid, old null or writable.
        ret_isize(unsafe { sys4(nr::TIMER_SETTIME, timerid as usize as i32 as usize, flags as usize, new as usize, old as usize) }) as i32
    }

    // # C: int timer_gettime(timer_t timerid, struct itimerspec *curr)
    #[no_mangle]
    pub unsafe extern "C" fn timer_gettime(timerid: *mut c_void, curr: *mut itimerspec) -> i32 {
        // SAFETY: timerid carries the kernel timer id; curr is writable.
        ret_isize(unsafe { sys3(nr::TIMER_GETTIME, timerid as usize as i32 as usize, curr as usize, 0) }) as i32
    }

    // # C: int timer_getoverrun(timer_t timerid)
    #[no_mangle]
    pub extern "C" fn timer_getoverrun(timerid: *mut c_void) -> i32 {
        // SAFETY: timerid carries the kernel timer id; no memory access.
        ret_isize(unsafe { sys1(nr::TIMER_GETOVERRUN, timerid as usize as i32 as usize) }) as i32
    }

    // # C: int timer_delete(timer_t timerid)
    #[no_mangle]
    pub extern "C" fn timer_delete(timerid: *mut c_void) -> i32 {
        // SAFETY: timerid carries the kernel timer id; no memory access.
        ret_isize(unsafe { sys1(nr::TIMER_DELETE, timerid as usize as i32 as usize) }) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn struct_abi() {
        assert_eq!(core::mem::size_of::<itimerspec>(), core::mem::size_of::<libc::itimerspec>());
        assert_eq!(core::mem::size_of::<sigevent>(), core::mem::size_of::<libc::sigevent>());
    }
}
