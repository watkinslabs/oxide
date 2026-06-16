// Process control + interval timers (docs/59§6 G8): alarm, getitimer/
// setitimer, times, clock, sleep, select/pselect6, settimeofday, stime,
// getgroups, the seteuid/setegid/setreuid/setregid credential aliases,
// setpgrp, getumask. struct itimerval / tms / timeval layouts match host
// <sys/time.h> / <sys/times.h> exactly.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys1, sys2, sys3, sys6};
use crate::internal::errno::{ret, ret_isize};
use crate::internal::nr;
use crate::time::clock::{timespec, timeval};

const ITIMER_REAL: i32 = 0;
// CLOCK_PROCESS_CPUTIME_ID per <time.h>; clock() reads it for CPU time.
const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
// CLOCKS_PER_SEC (<time.h>): clock() returns CPU time in 1/1e6 s units.
const CLOCKS_PER_SEC: i64 = 1_000_000;
// clock_t = long; clock() returns -1 on failure.
const CLOCK_FAIL: i64 = -1;
// _SC_CLK_TCK fixed at 100 on Linux (times() ticks per second).
const CLK_TCK: i64 = 100;

// struct itimerval { struct timeval it_interval, it_value; } — 32 bytes.
#[repr(C)]
pub struct itimerval { pub it_interval: timeval, pub it_value: timeval }

// struct tms { clock_t tms_utime, tms_stime, tms_cutime, tms_cstime; } — 32 B.
#[repr(C)]
pub struct tms { pub tms_utime: i64, pub tms_stime: i64, pub tms_cutime: i64, pub tms_cstime: i64 }

// # C: unsigned int alarm(unsigned int seconds)
#[no_mangle]
pub unsafe extern "C" fn alarm(seconds: u32) -> u32 {
    // SAFETY: alarm composes from setitimer(ITIMER_REAL) on both arches
    // (aarch64 asm-generic has no alarm slot); reads the old value back and
    // returns its remaining whole seconds (rounded up), per alarm(2)/glibc.
    unsafe {
        let new = itimerval {
            it_interval: timeval { tv_sec: 0, tv_usec: 0 },
            it_value: timeval { tv_sec: seconds as i64, tv_usec: 0 },
        };
        let mut old = itimerval {
            it_interval: timeval { tv_sec: 0, tv_usec: 0 },
            it_value: timeval { tv_sec: 0, tv_usec: 0 },
        };
        if setitimer(ITIMER_REAL, &new, &mut old) < 0 { return 0; }
        let mut secs = old.it_value.tv_sec;
        if old.it_value.tv_usec != 0 { secs += 1; }
        secs as u32
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn raw_getitimer(which: i32, cur: *mut itimerval) -> isize {
    // SAFETY: x86_64 getitimer(2) slot; cur is a valid itimerval out-param.
    unsafe { sys2(nr::GETITIMER, which as usize, cur as usize) }
}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn raw_getitimer(which: i32, cur: *mut itimerval) -> isize {
    // SAFETY: aarch64 getitimer(2) slot; cur is a valid itimerval out-param.
    unsafe { sys2(nr::GETITIMER, which as usize, cur as usize) }
}

// # C: int getitimer(int which, struct itimerval *curr_value)
#[no_mangle]
pub unsafe extern "C" fn getitimer(which: i32, curr_value: *mut itimerval) -> i32 {
    // SAFETY: getitimer(2); curr_value is a valid itimerval out-pointer.
    ret_isize(unsafe { raw_getitimer(which, curr_value) }) as i32
}
// # C: int setitimer(int which, const struct itimerval *new, struct itimerval *old)
#[no_mangle]
pub unsafe extern "C" fn setitimer(which: i32, new_value: *const itimerval, old_value: *mut itimerval) -> i32 {
    // SAFETY: setitimer(2); new_value valid, old_value null or a valid out.
    ret_isize(unsafe { sys3(nr::SETITIMER, which as usize, new_value as usize, old_value as usize) }) as i32
}

// # C: clock_t times(struct tms *buf)
#[no_mangle]
pub unsafe extern "C" fn times(buf: *mut tms) -> i64 {
    // SAFETY: times(2) fills buf (null allowed) and returns ticks since an
    // arbitrary epoch; the raw return is the clock_t value, -1 on error.
    let r = unsafe { sys1(nr::TIMES, buf as usize) };
    match ret(r) { Ok(v) => v as i64, Err(e) => { crate::internal::errno::set(e); -1 } }
}

// # C: clock_t clock(void) — process CPU time scaled to CLOCKS_PER_SEC.
#[no_mangle]
pub unsafe extern "C" fn clock() -> i64 {
    // SAFETY: reads CLOCK_PROCESS_CPUTIME_ID via clock_gettime and scales
    // ns → CLOCKS_PER_SEC (1e6) units, the glibc clock() convention.
    unsafe {
        let mut ts = timespec { tv_sec: 0, tv_nsec: 0 };
        if crate::time::clock::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mut ts) != 0 { return CLOCK_FAIL; }
        ts.tv_sec * CLOCKS_PER_SEC + ts.tv_nsec / (1_000_000_000 / CLOCKS_PER_SEC)
    }
}

// # C: unsigned int sleep(unsigned int seconds)
#[no_mangle]
pub unsafe extern "C" fn sleep(seconds: u32) -> u32 {
    // SAFETY: nanosleep loop; on EINTR the remaining time is fed back so the
    // call resumes, returning unslept seconds (rounded up) per sleep(3).
    unsafe {
        let mut req = timespec { tv_sec: seconds as i64, tv_nsec: 0 };
        let mut rem = timespec { tv_sec: 0, tv_nsec: 0 };
        loop {
            if crate::time::clock::nanosleep(&req, &mut rem) == 0 { return 0; }
            if *crate::internal::errno::__errno_location() != EINTR {
                let mut s = rem.tv_sec; if rem.tv_nsec != 0 { s += 1; } return s as u32;
            }
            req = timespec { tv_sec: rem.tv_sec, tv_nsec: rem.tv_nsec };
        }
    }
}
const EINTR: i32 = 4;

// fd_set: 1024-bit mask of longs (FD_SETSIZE=1024, NFDBITS=64). 128 bytes.
const FD_SETSIZE: usize = 1024;
#[repr(C)]
pub struct fd_set { pub fds_bits: [u64; FD_SETSIZE / 64] }

// # C: int select(int nfds, fd_set *r, fd_set *w, fd_set *e, struct timeval *to)
#[no_mangle]
pub unsafe extern "C" fn select(nfds: i32, readfds: *mut fd_set, writefds: *mut fd_set, exceptfds: *mut fd_set, timeout: *mut timeval) -> i32 {
    // SAFETY: fd_set pointers are null or valid 128-byte masks; on x86_64 the
    // select(2) slot is used directly, elsewhere pselect6 with a converted
    // timespec + NULL sigmask (the asm-generic composition, like io.rs).
    unsafe { do_select(nfds, readfds, writefds, exceptfds, timeout) }
}

#[cfg(target_arch = "x86_64")]
unsafe fn do_select(nfds: i32, r: *mut fd_set, w: *mut fd_set, e: *mut fd_set, to: *mut timeval) -> i32 {
    // SAFETY: x86_64 select(2); the kernel updates *to with remaining time.
    ret_isize(unsafe { sys6(nr::SELECT, nfds as usize, r as usize, w as usize, e as usize, to as usize, 0) }) as i32
}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn do_select(nfds: i32, r: *mut fd_set, w: *mut fd_set, e: *mut fd_set, to: *mut timeval) -> i32 {
    // SAFETY: aarch64 composes select from pselect6; convert the timeval to a
    // timespec on the stack and pass a NULL sigmask (6th arg is sigset+size).
    unsafe {
        let mut ts = timespec { tv_sec: 0, tv_nsec: 0 };
        let tsp = if to.is_null() { core::ptr::null_mut() } else {
            ts.tv_sec = (*to).tv_sec; ts.tv_nsec = (*to).tv_usec * 1000; &mut ts as *mut timespec
        };
        ret_isize(sys6(nr::PSELECT6, nfds as usize, r as usize, w as usize, e as usize, tsp as usize, 0)) as i32
    }
}

// # C: int pselect(int nfds, fd_set*, fd_set*, fd_set*, const timespec*, const sigset_t*)
#[no_mangle]
pub unsafe extern "C" fn pselect(nfds: i32, r: *mut fd_set, w: *mut fd_set, e: *mut fd_set, to: *const timespec, sigmask: *const core::ffi::c_void) -> i32 {
    // SAFETY: pselect6(2) takes the sigmask as a {ptr,size} pair packed in a
    // 7-word struct via the 6th arg; glibc passes a 2-word block on the stack.
    unsafe {
        let pack: [usize; 2] = [sigmask as usize, 8]; // _NSIG/8 = 8 bytes
        let mp = if sigmask.is_null() { core::ptr::null() } else { pack.as_ptr() };
        ret_isize(sys6(nr::PSELECT6, nfds as usize, r as usize, w as usize, e as usize, to as usize, mp as usize)) as i32
    }
}

// poll(2): one entry per fd, kernel sets `revents`. (`struct pollfd`.)
#[repr(C)]
pub struct pollfd { pub fd: i32, pub events: i16, pub revents: i16 }

// # C: int poll(struct pollfd *fds, nfds_t nfds, int timeout)
// Composed from ppoll like glibc: the plain poll(2) slot is legacy; modern
// glibc routes through ppoll. timeout < 0 = block forever (NULL timespec);
// else convert milliseconds to a timespec. NULL sigmask, 0 sigsetsize.
#[no_mangle]
pub unsafe extern "C" fn poll(fds: *mut pollfd, nfds: u64, timeout: i32) -> i32 {
    // SAFETY: fds is null or an array of `nfds` pollfd the kernel reads/writes;
    // ts lives on this frame for the syscall's duration.
    unsafe {
        let mut ts = timespec { tv_sec: 0, tv_nsec: 0 };
        let tsp = if timeout < 0 { core::ptr::null::<timespec>() } else {
            ts.tv_sec = (timeout / 1000) as i64;
            ts.tv_nsec = ((timeout % 1000) as i64) * 1_000_000;
            &ts as *const timespec
        };
        ret_isize(sys6(nr::PPOLL, fds as usize, nfds as usize, tsp as usize, 0, 8, 0)) as i32
    }
}

// # C: int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo,
//               const sigset_t *sigmask)
#[no_mangle]
pub unsafe extern "C" fn ppoll(fds: *mut pollfd, nfds: u64, tmo: *const timespec, sigmask: *const core::ffi::c_void) -> i32 {
    // SAFETY: ppoll(2) — sigmask is a {ptr}+size pair (size = _NSIG/8 = 8);
    // NULL sigmask passes a null pointer with size 0 (glibc convention).
    unsafe {
        let (mp, sz) = if sigmask.is_null() { (0usize, 0usize) } else { (sigmask as usize, 8usize) };
        ret_isize(sys6(nr::PPOLL, fds as usize, nfds as usize, tmo as usize, mp, sz, 0)) as i32
    }
}

// # C: int settimeofday(const struct timeval *tv, const struct timezone *tz)
#[no_mangle]
pub unsafe extern "C" fn settimeofday(tv: *const timeval, tz: *const core::ffi::c_void) -> i32 {
    // SAFETY: settimeofday(2); tv null or a valid timeval, tz typically NULL.
    ret_isize(unsafe { sys2(nr::SETTIMEOFDAY, tv as usize, tz as usize) }) as i32
}
// # C: int stime(const time_t *t) — set wall clock from seconds.
#[no_mangle]
pub unsafe extern "C" fn stime(t: *const i64) -> i32 {
    // SAFETY: stime composes from settimeofday(tv={*t,0}, NULL); t is a valid
    // time_t pointer per stime(2).
    unsafe {
        if t.is_null() { crate::internal::errno::set(EFAULT); return -1; }
        let tv = timeval { tv_sec: *t, tv_usec: 0 };
        settimeofday(&tv, core::ptr::null())
    }
}
const EFAULT: i32 = 14;

// # C: int getgroups(int size, gid_t list[])
#[no_mangle]
pub unsafe extern "C" fn getgroups(size: i32, list: *mut u32) -> i32 {
    // SAFETY: getgroups(2); list holds `size` gid_t slots (null when size==0,
    // the "how many groups?" query form).
    ret_isize(unsafe { sys2(nr::GETGROUPS, size as usize, list as usize) }) as i32
}

// credential aliases composed over setres{u,g}id (the modern primitives).
const NEG1: usize = usize::MAX; // (uid_t)-1 = "leave unchanged"

// # C: int seteuid(uid_t euid)
#[no_mangle]
pub unsafe extern "C" fn seteuid(euid: u32) -> i32 {
    // SAFETY: setresuid(-1, euid, -1) sets only the effective uid; no memory.
    ret_isize(unsafe { sys3(nr::SETRESUID, NEG1, euid as usize, NEG1) }) as i32
}
// # C: int setegid(gid_t egid)
#[no_mangle]
pub unsafe extern "C" fn setegid(egid: u32) -> i32 {
    // SAFETY: setresgid(-1, egid, -1) sets only the effective gid; no memory.
    ret_isize(unsafe { sys3(nr::SETRESGID, NEG1, egid as usize, NEG1) }) as i32
}
// # C: int setreuid(uid_t ruid, uid_t euid)
#[no_mangle]
pub unsafe extern "C" fn setreuid(ruid: u32, euid: u32) -> i32 {
    // SAFETY: setreuid(2) scalar ids; no memory dereferenced.
    ret_isize(unsafe { sys2(nr::SETREUID, ruid as usize, euid as usize) }) as i32
}
// # C: int setregid(gid_t rgid, gid_t egid)
#[no_mangle]
pub unsafe extern "C" fn setregid(rgid: u32, egid: u32) -> i32 {
    // SAFETY: setregid(2) scalar ids; no memory dereferenced.
    ret_isize(unsafe { sys2(nr::SETREGID, rgid as usize, egid as usize) }) as i32
}
// # C: int setresuid(uid_t ruid, uid_t euid, uid_t suid)
#[no_mangle]
pub unsafe extern "C" fn setresuid(ruid: u32, euid: u32, suid: u32) -> i32 {
    // SAFETY: setresuid(2) scalar ids; no memory dereferenced.
    ret_isize(unsafe { sys3(nr::SETRESUID, ruid as usize, euid as usize, suid as usize) }) as i32
}
// # C: int setresgid(gid_t rgid, gid_t egid, gid_t sgid)
#[no_mangle]
pub unsafe extern "C" fn setresgid(rgid: u32, egid: u32, sgid: u32) -> i32 {
    // SAFETY: setresgid(2) scalar ids; no memory dereferenced.
    ret_isize(unsafe { sys3(nr::SETRESGID, rgid as usize, egid as usize, sgid as usize) }) as i32
}

// # C: int setpgrp(void) — BSD/SysV setpgid(0, 0).
#[no_mangle]
pub unsafe extern "C" fn setpgrp() -> i32 {
    // SAFETY: setpgid(0,0) makes the caller its own pgrp leader; no memory.
    ret_isize(unsafe { sys2(nr::SETPGID, 0, 0) }) as i32
}

// # C: mode_t getumask(void) — read the current umask without changing it.
#[no_mangle]
pub unsafe extern "C" fn getumask() -> u32 {
    // SAFETY: umask(2) is read-write only, so glibc temporarily sets a known
    // value, reads the old one, restores it. Single-threaded-safe; racy under
    // threads exactly as glibc's getumask is. UMASK syscall touches no memory.
    unsafe {
        let old = sys1(nr::UMASK, 0o22) as u32; // set then read old
        sys1(nr::UMASK, old as usize); // restore
        old
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn struct_sizes_match_host() {
        assert_eq!(core::mem::size_of::<itimerval>(), 32);
        assert_eq!(core::mem::size_of::<tms>(), 32);
        assert_eq!(core::mem::size_of::<fd_set>(), 128);
        assert_eq!(CLOCKS_PER_SEC, 1_000_000);
        assert_eq!(CLK_TCK, 100);
    }
}
