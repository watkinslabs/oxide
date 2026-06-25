// Clocks + sleep (docs/59§6 G10). Syscall wrappers; gettimeofday/time
// derive from clock_gettime(REALTIME) so both arches share one path.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys2, sys4};
use crate::internal::errno::ret_isize;
use crate::internal::nr;

pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;

// # C: int clock_getcpuclockid(pid_t pid, clockid_t *clock_id)
// Encodes the per-PROCESS CPU clock the kernel posix-cpu-timers expects:
// (~pid<<3)|CPUCLOCK_SCHED. pid 0 = the calling process.
#[no_mangle]
pub unsafe extern "C" fn clock_getcpuclockid(pid: i32, clock_id: *mut i32) -> i32 {
    // SAFETY: clock_id is a writable clockid_t out-param.
    unsafe { *clock_id = (!pid << 3) | 2 /* CPUCLOCK_SCHED */; }
    0
}

#[repr(C)]
pub struct timespec { pub tv_sec: i64, pub tv_nsec: i64 }
#[repr(C)]
pub struct timeval { pub tv_sec: i64, pub tv_usec: i64 }
#[repr(C)]
pub struct timeb { pub time: i64, pub millitm: u16, pub timezone: i16, pub dstflag: i16 }
const _: () = assert!(core::mem::size_of::<timeb>() == 16);

// # C: int clock_gettime(clockid_t clk, struct timespec *ts)
#[no_mangle]
pub unsafe extern "C" fn clock_gettime(clk: i32, ts: *mut timespec) -> i32 {
    // SAFETY: ts is a valid timespec out-param per clock_gettime(2).
    ret_isize(unsafe { sys2(nr::CLOCK_GETTIME, clk as usize, ts as usize) }) as i32
}
// # C: int __clock_gettime(clockid_t clk, struct timespec *ts)
#[no_mangle]
pub unsafe extern "C" fn __clock_gettime(clk: i32, ts: *mut timespec) -> i32 {
    // SAFETY: __clock_gettime has the same timespec out-param contract as clock_gettime.
    unsafe { clock_gettime(clk, ts) }
}
// # C: int clock_getres(clockid_t clk, struct timespec *res)
#[no_mangle]
pub unsafe extern "C" fn clock_getres(clk: i32, res: *mut timespec) -> i32 {
    // SAFETY: res is null or a valid timespec out-param.
    ret_isize(unsafe { sys2(nr::CLOCK_GETRES, clk as usize, res as usize) }) as i32
}
// # C: int nanosleep(const struct timespec *req, struct timespec *rem)
#[no_mangle]
pub unsafe extern "C" fn nanosleep(req: *const timespec, rem: *mut timespec) -> i32 {
    // SAFETY: req is a valid timespec; rem is null or writable.
    ret_isize(unsafe { sys2(nr::NANOSLEEP, req as usize, rem as usize) }) as i32
}
// # C: int __nanosleep(const struct timespec *req, struct timespec *rem)
#[no_mangle]
pub unsafe extern "C" fn __nanosleep(req: *const timespec, rem: *mut timespec) -> i32 {
    // SAFETY: __nanosleep has the same timespec pointer contract as nanosleep.
    unsafe { nanosleep(req, rem) }
}
// # C: int clock_nanosleep(clockid_t, int flags, const timespec*, timespec*)
#[no_mangle]
pub unsafe extern "C" fn clock_nanosleep(clk: i32, flags: i32, req: *const timespec, rem: *mut timespec) -> i32 {
    // SAFETY: req valid; rem null or writable. Returns errno directly (not
    // via errno) per clock_nanosleep — but glibc returns it; we mirror.
    let r = unsafe { sys4(nr::CLOCK_NANOSLEEP, clk as usize, flags as usize, req as usize, rem as usize) };
    if r < 0 { -r as i32 } else { 0 }
}
// # C: int gettimeofday(struct timeval *tv, void *tz)
#[no_mangle]
pub unsafe extern "C" fn gettimeofday(tv: *mut timeval, _tz: *mut core::ffi::c_void) -> i32 {
    // SAFETY: tv is null or a valid timeval; derive from REALTIME clock.
    unsafe {
        if tv.is_null() { return 0; }
        let mut ts = timespec { tv_sec: 0, tv_nsec: 0 };
        let r = clock_gettime(CLOCK_REALTIME, &mut ts);
        if r == 0 { (*tv).tv_sec = ts.tv_sec; (*tv).tv_usec = ts.tv_nsec / 1000; }
        r
    }
}
// # C: time_t time(time_t *t)
#[no_mangle]
pub unsafe extern "C" fn time(t: *mut i64) -> i64 {
    // SAFETY: t is null or a valid time_t out-param.
    unsafe {
        let mut ts = timespec { tv_sec: 0, tv_nsec: 0 };
        if clock_gettime(CLOCK_REALTIME, &mut ts) != 0 { return -1; }
        if !t.is_null() { *t = ts.tv_sec; }
        ts.tv_sec
    }
}

// # C: int ftime(struct timeb *timebuf)
#[no_mangle]
pub unsafe extern "C" fn ftime(timebuf: *mut timeb) -> i32 {
    // SAFETY: timebuf is a valid timeb out-param; derive seconds and
    // milliseconds from CLOCK_REALTIME like glibc's legacy wrapper.
    unsafe {
        let mut ts = timespec { tv_sec: 0, tv_nsec: 0 };
        let r = clock_gettime(CLOCK_REALTIME, &mut ts);
        if r != 0 { return r; }
        if !timebuf.is_null() {
            (*timebuf).time = ts.tv_sec;
            (*timebuf).millitm = (ts.tv_nsec / 1_000_000) as u16;
            (*timebuf).timezone = 0;
            (*timebuf).dstflag = 0;
        }
        0
    }
}
