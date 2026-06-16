// C11 <threads.h> (docs/59§6 §9.1). Thin shims over the pthread surface: the
// C11 thrd_t/mtx_t/cnd_t/tss_t/once_flag are layout-compatible with the
// pthread types, so we cast. C11 returns its own codes (thrd_success/busy/
// error/nomem/timedout), mapped from the pthread errno returns.
#![cfg(feature = "freestanding")]
use core::ffi::c_void;
use crate::malloc::heap;
use crate::time::clock::timespec;

const THRD_SUCCESS: i32 = 0;
const THRD_BUSY: i32 = 1;
const THRD_ERROR: i32 = 2;
const THRD_NOMEM: i32 = 3;
const THRD_TIMEDOUT: i32 = 4;

// Map a pthread errno return (0 ok / positive errno) to a C11 thrd_* code.
fn map(e: i32) -> i32 {
    match e { 0 => THRD_SUCCESS, 16 => THRD_BUSY, 110 => THRD_TIMEDOUT, 12 => THRD_NOMEM, _ => THRD_ERROR }
}

type ThrdStart = extern "C" fn(*mut c_void) -> i32;
#[repr(C)]
struct Box { func: ThrdStart, arg: *mut c_void }

// pthread start routine: unbox, run the C11 func, return its int as the retval.
extern "C" fn trampoline(p: *mut c_void) -> *mut c_void {
    // SAFETY: p is the heap Box from thrd_create; we own it, read func+arg,
    // free it, then run func(arg) and pack the int result into the void* retval.
    unsafe {
        let b = p as *mut Box;
        let (func, arg) = ((*b).func, (*b).arg);
        heap::free(b as *mut u8);
        func(arg) as isize as *mut c_void
    }
}

// # C: int thrd_create(thrd_t *thr, thrd_start_t func, void *arg)
#[no_mangle]
pub unsafe extern "C" fn thrd_create(thr: *mut usize, func: ThrdStart, arg: *mut c_void) -> i32 {
    // SAFETY: thr is a writable thrd_t; box func+arg on the heap for the new
    // thread's trampoline, then pthread_create.
    unsafe {
        let b = heap::malloc(core::mem::size_of::<Box>()) as *mut Box;
        if b.is_null() { return THRD_NOMEM; }
        (*b).func = func; (*b).arg = arg;
        let r = super::pthread_create(thr, core::ptr::null(), trampoline, b as *mut c_void);
        if r != 0 { heap::free(b as *mut u8); }
        map(r)
    }
}
// # C: int thrd_join(thrd_t thr, int *res)
#[no_mangle]
pub unsafe extern "C" fn thrd_join(thr: usize, res: *mut i32) -> i32 {
    // SAFETY: thr is a joinable thrd_t; unpack the int from the void* retval.
    unsafe {
        let mut rv: *mut c_void = core::ptr::null_mut();
        let r = super::pthread_join(thr, &mut rv);
        if !res.is_null() { *res = rv as isize as i32; }
        map(r)
    }
}
// # C: thrd_t thrd_current(void)
#[no_mangle]
pub unsafe extern "C" fn thrd_current() -> usize {
    // SAFETY: returns this thread's pthread_t (TCB pointer).
    unsafe { super::pthread_self() }
}
// # C: int thrd_detach(thrd_t thr)
#[no_mangle]
pub unsafe extern "C" fn thrd_detach(thr: usize) -> i32 {
    // SAFETY: thr is a valid thrd_t; forward to pthread_detach.
    unsafe { map(super::pthread_detach(thr)) }
}
// # C: int thrd_equal(thrd_t a, thrd_t b)
#[no_mangle]
pub extern "C" fn thrd_equal(a: usize, b: usize) -> i32 { (a == b) as i32 }
// # C: _Noreturn void thrd_exit(int res)
#[no_mangle]
pub unsafe extern "C" fn thrd_exit(res: i32) -> ! {
    // SAFETY: pack the int into the void* retval and terminate this thread.
    unsafe { super::pthread_exit(res as isize as *mut c_void) }
}
// # C: int thrd_sleep(const struct timespec *duration, struct timespec *remaining)
#[no_mangle]
pub unsafe extern "C" fn thrd_sleep(duration: *const timespec, remaining: *mut timespec) -> i32 {
    // SAFETY: nanosleep returns 0, or -1/errno; C11 wants 0 / -1 (interrupted)
    // / -2 (other). EINTR(-4) maps to -1.
    unsafe {
        let r = crate::time::clock::nanosleep(duration, remaining);
        if r == 0 { 0 } else if *crate::internal::errno::__errno_location() == 4 { -1 } else { -2 }
    }
}
// # C: void thrd_yield(void)
#[no_mangle]
pub unsafe extern "C" fn thrd_yield() {
    // SAFETY: sched_yield via the pthread_yield wrapper; result ignored.
    unsafe { super::control::pthread_yield(); }
}

// --- mtx_t (cast to pthread_mutex_t) ---------------------------------------
// # C: int mtx_init(mtx_t *m, int type)
#[no_mangle]
pub unsafe extern "C" fn mtx_init(m: *mut c_void, ty: i32) -> i32 {
    // SAFETY: m is a writable mtx_t (== pthread_mutex_t). Recursive bit maps to
    // PTHREAD_MUTEX_RECURSIVE; otherwise default. mtx_timed needs no special
    // init (mtx_timedlock works on any mutex).
    unsafe {
        let mp = m as *mut super::mutex::pthread_mutex_t;
        if ty & 1 != 0 { // mtx_recursive
            let mut a: i32 = 0;
            super::mutex::pthread_mutexattr_settype(&mut a as *mut i32 as *mut _, 1);
            super::mutex::pthread_mutex_init(mp, &a as *const i32 as *const _)
        } else {
            super::mutex::pthread_mutex_init(mp, core::ptr::null())
        };
        THRD_SUCCESS
    }
}
// # C: int mtx_lock(mtx_t *m)
#[no_mangle]
pub unsafe extern "C" fn mtx_lock(m: *mut c_void) -> i32 {
    // SAFETY: m is a live mtx_t (== pthread_mutex_t).
    unsafe { map(super::mutex::pthread_mutex_lock(m as *mut _)) }
}
// # C: int mtx_trylock(mtx_t *m)
#[no_mangle]
pub unsafe extern "C" fn mtx_trylock(m: *mut c_void) -> i32 {
    // SAFETY: m is a live mtx_t (== pthread_mutex_t); non-blocking attempt.
    unsafe { map(super::mutex::pthread_mutex_trylock(m as *mut _)) }
}
// # C: int mtx_timedlock(mtx_t *m, const struct timespec *ts)
#[no_mangle]
pub unsafe extern "C" fn mtx_timedlock(m: *mut c_void, ts: *const c_void) -> i32 {
    // SAFETY: m is a live mtx_t; ts an absolute deadline.
    unsafe { map(super::mutex::pthread_mutex_timedlock(m as *mut _, ts)) }
}
// # C: int mtx_unlock(mtx_t *m)
#[no_mangle]
pub unsafe extern "C" fn mtx_unlock(m: *mut c_void) -> i32 {
    // SAFETY: m is a live mtx_t held by this thread; release it.
    unsafe { map(super::mutex::pthread_mutex_unlock(m as *mut _)) }
}
// # C: void mtx_destroy(mtx_t *m)
#[no_mangle]
pub unsafe extern "C" fn mtx_destroy(m: *mut c_void) {
    // SAFETY: m is a mtx_t (== pthread_mutex_t) no longer in use; reclaim it.
    unsafe { super::mutex::pthread_mutex_destroy(m as *mut _); }
}

// --- cnd_t (cast to pthread_cond_t) ----------------------------------------
// # C: int cnd_init(cnd_t *c)
#[no_mangle]
pub unsafe extern "C" fn cnd_init(c: *mut c_void) -> i32 {
    // SAFETY: c is a writable cnd_t (== pthread_cond_t).
    unsafe { map(super::cond::pthread_cond_init(c as *mut _, core::ptr::null())) }
}
// # C: int cnd_signal(cnd_t *c)
#[no_mangle]
pub unsafe extern "C" fn cnd_signal(c: *mut c_void) -> i32 {
    // SAFETY: c is a live cnd_t (== pthread_cond_t); wake one waiter.
    unsafe { map(super::cond::pthread_cond_signal(c as *mut _)) }
}
// # C: int cnd_broadcast(cnd_t *c)
#[no_mangle]
pub unsafe extern "C" fn cnd_broadcast(c: *mut c_void) -> i32 {
    // SAFETY: c is a live cnd_t (== pthread_cond_t); wake all waiters.
    unsafe { map(super::cond::pthread_cond_broadcast(c as *mut _)) }
}
// # C: int cnd_wait(cnd_t *c, mtx_t *m)
#[no_mangle]
pub unsafe extern "C" fn cnd_wait(c: *mut c_void, m: *mut c_void) -> i32 {
    // SAFETY: c/m are live cnd_t/mtx_t; m held by the caller.
    unsafe { map(super::cond::pthread_cond_wait(c as *mut _, m as *mut _)) }
}
// # C: int cnd_timedwait(cnd_t *c, mtx_t *m, const struct timespec *ts)
#[no_mangle]
pub unsafe extern "C" fn cnd_timedwait(c: *mut c_void, m: *mut c_void, ts: *const timespec) -> i32 {
    // SAFETY: c/m live, m held; ts an absolute deadline.
    unsafe { map(super::cond::pthread_cond_timedwait(c as *mut _, m as *mut _, ts)) }
}
// # C: void cnd_destroy(cnd_t *c)
#[no_mangle]
pub unsafe extern "C" fn cnd_destroy(c: *mut c_void) {
    // SAFETY: c is a cnd_t (== pthread_cond_t) no longer in use; reclaim it.
    unsafe { super::cond::pthread_cond_destroy(c as *mut _); }
}

// --- tss_t (== pthread_key_t) + call_once ----------------------------------
// # C: int tss_create(tss_t *key, tss_dtor_t dtor)
#[no_mangle]
pub unsafe extern "C" fn tss_create(key: *mut u32, dtor: Option<extern "C" fn(*mut c_void)>) -> i32 {
    // SAFETY: key is a writable tss_t (== pthread_key_t).
    unsafe { map(super::key::pthread_key_create(key, dtor)) }
}
// # C: void tss_delete(tss_t key)
#[no_mangle]
pub unsafe extern "C" fn tss_delete(key: u32) {
    // SAFETY: key is a valid tss_t (== pthread_key_t) to release.
    unsafe { super::key::pthread_key_delete(key); }
}
// # C: void *tss_get(tss_t key)
#[no_mangle]
pub unsafe extern "C" fn tss_get(key: u32) -> *mut c_void {
    // SAFETY: key is a valid tss_t (== pthread_key_t); read this thread's value.
    unsafe { super::key::pthread_getspecific(key) }
}
// # C: int tss_set(tss_t key, void *val)
#[no_mangle]
pub unsafe extern "C" fn tss_set(key: u32, val: *mut c_void) -> i32 {
    // SAFETY: key is a valid tss_t (== pthread_key_t); set this thread's value.
    unsafe { map(super::key::pthread_setspecific(key, val)) }
}
// # C: void call_once(once_flag *flag, void (*func)(void))
#[no_mangle]
pub unsafe extern "C" fn call_once(flag: *mut c_void, func: extern "C" fn()) {
    // SAFETY: flag is a once_flag (== pthread_once_t); forward to pthread_once.
    unsafe { super::once::pthread_once(flag as *mut _, func); }
}
