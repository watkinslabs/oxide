// rt/sem — POSIX unnamed semaphores (docs/59§6 G17b). sem_t is the 32-byte
// glibc union; its first 4 bytes are the value + futex word. The decrement/
// increment transitions are a pure state machine (hosted-tested); the C ABI
// wraps them with FUTEX_WAIT/FUTEX_WAKE.
#[repr(C)]
pub struct sem_t { __size: [u8; 32] }
const _: () = assert!(core::mem::size_of::<sem_t>() == 32);

/// Try to take one token: Some(v-1) if available, None if it would block.
/// # C: semaphore try-decrement transition
pub(crate) fn try_dec(v: u32) -> Option<u32> { if v > 0 { Some(v - 1) } else { None } }
/// Release one token.
/// # C: semaphore post transition
pub(crate) fn inc(v: u32) -> u32 { v + 1 }

#[cfg(feature = "freestanding")]
pub use imp::*;

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use crate::arch::syscall::sys6;
    use crate::internal::{errno, nr};
    use crate::time::clock::{clock_gettime, timespec, CLOCK_REALTIME};
    use core::sync::atomic::{AtomicU32, Ordering};

    const FUTEX_WAIT_PRIVATE: usize = 128;
    const FUTEX_WAKE_PRIVATE: usize = 129;
    const EAGAIN: i32 = 11;
    const ETIMEDOUT: i32 = 110;

    unsafe fn word<'a>(s: *mut sem_t) -> &'a AtomicU32 {
        // SAFETY: the sem_t union is long-aligned; its first 4 bytes are the
        // value/futex word, so reinterpreting the start as AtomicU32 is valid.
        unsafe { &*(s as *const AtomicU32) }
    }

    // # C: int sem_init(sem_t *sem, int pshared, unsigned int value)
    #[no_mangle]
    pub unsafe extern "C" fn sem_init(s: *mut sem_t, _pshared: i32, value: u32) -> i32 {
        // SAFETY: s points to a caller-owned sem_t; set its value word.
        unsafe { word(s).store(value, Ordering::Release); }
        0
    }
    // # C: int sem_destroy(sem_t *sem)
    #[no_mangle]
    pub extern "C" fn sem_destroy(_s: *mut sem_t) -> i32 { 0 }

    // # C: int sem_post(sem_t *sem)
    #[no_mangle]
    pub unsafe extern "C" fn sem_post(s: *mut sem_t) -> i32 {
        // SAFETY: s valid; increment the value and wake one waiter.
        unsafe {
            word(s).fetch_add(1, Ordering::Release);
            sys6(nr::FUTEX, s as usize, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
        }
        0
    }

    // # C: int sem_trywait(sem_t *sem)
    #[no_mangle]
    pub unsafe extern "C" fn sem_trywait(s: *mut sem_t) -> i32 {
        // SAFETY: s valid; CAS-decrement if positive, else EAGAIN.
        unsafe {
            let w = word(s);
            loop {
                let v = w.load(Ordering::Acquire);
                match try_dec(v) {
                    None => { errno::set(EAGAIN); return -1; }
                    Some(nv) => if w.compare_exchange_weak(v, nv, Ordering::AcqRel, Ordering::Acquire).is_ok() { return 0; }
                }
            }
        }
    }

    // Block until a token is available; abstime null = forever, else an
    // absolute CLOCK_REALTIME deadline.
    unsafe fn wait_common(s: *mut sem_t, abstime: *const timespec) -> i32 {
        // SAFETY: s valid; abstime null or a valid absolute deadline. Recompute
        // the relative FUTEX_WAIT timeout each iteration so the deadline holds
        // across spurious wakeups.
        unsafe {
            let w = word(s);
            loop {
                let v = w.load(Ordering::Acquire);
                if let Some(nv) = try_dec(v) {
                    if w.compare_exchange_weak(v, nv, Ordering::AcqRel, Ordering::Acquire).is_ok() { return 0; }
                    continue;
                }
                let mut rel = timespec { tv_sec: 0, tv_nsec: 0 };
                let relp = if abstime.is_null() {
                    core::ptr::null()
                } else {
                    let mut now = timespec { tv_sec: 0, tv_nsec: 0 };
                    clock_gettime(CLOCK_REALTIME, &mut now);
                    rel.tv_sec = (*abstime).tv_sec - now.tv_sec;
                    rel.tv_nsec = (*abstime).tv_nsec - now.tv_nsec;
                    if rel.tv_nsec < 0 { rel.tv_nsec += 1_000_000_000; rel.tv_sec -= 1; }
                    if rel.tv_sec < 0 { errno::set(ETIMEDOUT); return -1; }
                    &rel
                };
                let r = sys6(nr::FUTEX, s as usize, FUTEX_WAIT_PRIVATE, 0, relp as usize, 0, 0);
                if !abstime.is_null() && r == -(ETIMEDOUT as isize) { errno::set(ETIMEDOUT); return -1; }
            }
        }
    }

    // # C: int sem_wait(sem_t *sem)
    #[no_mangle]
    pub unsafe extern "C" fn sem_wait(s: *mut sem_t) -> i32 {
        // SAFETY: s valid; block until a token is available.
        unsafe { wait_common(s, core::ptr::null()) }
    }

    // # C: int sem_timedwait(sem_t *sem, const struct timespec *abstime)
    #[no_mangle]
    pub unsafe extern "C" fn sem_timedwait(s: *mut sem_t, abstime: *const timespec) -> i32 {
        // SAFETY: s valid; abstime is an absolute CLOCK_REALTIME deadline.
        unsafe { wait_common(s, abstime) }
    }

    // # C: int sem_getvalue(sem_t *sem, int *sval)
    #[no_mangle]
    pub unsafe extern "C" fn sem_getvalue(s: *mut sem_t, sval: *mut i32) -> i32 {
        // SAFETY: s/sval valid; report the current token count.
        unsafe { *sval = word(s).load(Ordering::Acquire) as i32; }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sem_t_abi() { assert_eq!(core::mem::size_of::<sem_t>(), core::mem::size_of::<libc::sem_t>()); }

    #[test]
    fn state_machine() {
        // post increments; trywait decrements; trywait at 0 blocks (None).
        let mut v = 0u32;
        assert_eq!(try_dec(v), None);
        v = inc(v);
        assert_eq!(v, 1);
        assert_eq!(try_dec(v), Some(0));
        v = inc(inc(v)); // 3
        assert_eq!(v, 3);
        let mut taken = 0;
        while let Some(nv) = try_dec(v) { v = nv; taken += 1; }
        assert_eq!(taken, 3);
        assert_eq!(try_dec(v), None);
    }
}
