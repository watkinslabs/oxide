// pthread attributes + GNU process-global default attr (docs/59§6 G11).
// pthread_attr_t is opaque (host __SIZEOF_PTHREAD_ATTR_T = 56 on x86_64); we
// overlay our own fields in the leading bytes — both get/set route through
// this code, so the in-memory layout is private. The default attr mirrors
// glibc: stacksize from RLIMIT_STACK, guardsize = one page, joinable, default
// sched. pthread_{get,set}attr_default_np read/replace the process-global copy.
#![cfg(feature = "freestanding")]
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};

const RLIMIT_STACK: i32 = 3;
const PAGE: usize = 4096;
const MIN_STACK: usize = 16 * 1024; // PTHREAD_STACK_MIN floor

// Our private view of pthread_attr_t. Fits inside the 56-byte opaque object.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Attr {
    pub detach: i32,        // 0 = joinable (PTHREAD_CREATE_JOINABLE), 1 = detached
    pub inherit: i32,       // sched inherit (0 = INHERIT_SCHED)
    pub policy: i32,        // SCHED_OTHER = 0
    pub guardsize: usize,
    pub stacksize: usize,
    pub stackaddr: usize,   // 0 = libc-allocated
}

impl Attr {
    fn default_attr() -> Attr {
        // glibc default stacksize = RLIMIT_STACK cur (finite) else 8 MiB.
        let mut st = 8 << 20;
        let mut rl = crate::posix::resource::Rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: rl is a stack-local writable rlimit out-param for getrlimit.
        let r = unsafe { crate::posix::resource::getrlimit(RLIMIT_STACK, &mut rl) };
        if r == 0 && rl.rlim_cur != crate::posix::resource::RLIM_INFINITY && rl.rlim_cur >= MIN_STACK as u64 {
            st = rl.rlim_cur as usize;
        }
        Attr { detach: 0, inherit: 0, policy: 0, guardsize: PAGE, stacksize: st, stackaddr: 0 }
    }
}

// Process-global default attr, lazily initialized on first access. Single
// global until the per-thread attr work; reads/writes are coarse (a flag +
// the cell), acceptable for the NULL-attr default path.
struct DefCell(UnsafeCell<Attr>);
// SAFETY: the default attr is a process-global; accesses are serialized by the
// INIT flag's acquire/release and the single-writer set path (G11 note).
unsafe impl Sync for DefCell {}
static DEFAULT: DefCell = DefCell(UnsafeCell::new(Attr {
    detach: 0, inherit: 0, policy: 0, guardsize: PAGE, stacksize: 8 << 20, stackaddr: 0,
}));
static INIT: AtomicBool = AtomicBool::new(false);

fn ensure_default() {
    if !INIT.swap(true, Ordering::AcqRel) {
        // SAFETY: first caller initializes the global default attr from the
        // RLIMIT_STACK-derived values before any reader observes INIT=true.
        unsafe { *DEFAULT.0.get() = Attr::default_attr(); }
    }
}

#[inline]
fn as_attr(p: *mut c_void) -> *mut Attr { p as *mut Attr }

// # C: int pthread_attr_init(pthread_attr_t *attr)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_init(attr: *mut c_void) -> i32 {
    // SAFETY: attr is a writable pthread_attr_t object (>= our Attr size).
    unsafe { *as_attr(attr) = Attr { detach: 0, inherit: 0, policy: 0, guardsize: PAGE, stacksize: 8 << 20, stackaddr: 0 }; }
    0
}
// # C: int pthread_attr_destroy(pthread_attr_t *attr) — no owned resources
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_destroy(_attr: *mut c_void) -> i32 { 0 }

// # C: int pthread_attr_setstacksize(pthread_attr_t *, size_t)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setstacksize(attr: *mut c_void, sz: usize) -> i32 {
    if sz < MIN_STACK { return 22; } // EINVAL
    // SAFETY: attr is a writable pthread_attr_t object.
    unsafe { (*as_attr(attr)).stacksize = sz; }
    0
}
// # C: int pthread_attr_getstacksize(const pthread_attr_t *, size_t *)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getstacksize(attr: *const c_void, out: *mut usize) -> i32 {
    // SAFETY: attr is an initialized pthread_attr_t; out is a writable size_t*.
    unsafe { *out = (*(attr as *const Attr)).stacksize; }
    0
}
// # C: int pthread_attr_setguardsize(pthread_attr_t *, size_t)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setguardsize(attr: *mut c_void, sz: usize) -> i32 {
    // SAFETY: attr is a writable pthread_attr_t object.
    unsafe { (*as_attr(attr)).guardsize = sz; }
    0
}
// # C: int pthread_attr_getguardsize(const pthread_attr_t *, size_t *)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getguardsize(attr: *const c_void, out: *mut usize) -> i32 {
    // SAFETY: attr is an initialized pthread_attr_t; out is a writable size_t*.
    unsafe { *out = (*(attr as *const Attr)).guardsize; }
    0
}
// # C: int pthread_attr_setdetachstate(pthread_attr_t *, int)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setdetachstate(attr: *mut c_void, state: i32) -> i32 {
    if state != 0 && state != 1 { return 22; } // EINVAL
    // SAFETY: attr is a writable pthread_attr_t object.
    unsafe { (*as_attr(attr)).detach = state; }
    0
}
// # C: int pthread_attr_getdetachstate(const pthread_attr_t *, int *)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getdetachstate(attr: *const c_void, out: *mut i32) -> i32 {
    // SAFETY: attr is an initialized pthread_attr_t; out is a writable int*.
    unsafe { *out = (*(attr as *const Attr)).detach; }
    0
}

// # C: int pthread_getattr_default_np(pthread_attr_t *attr)
#[no_mangle]
pub unsafe extern "C" fn pthread_getattr_default_np(attr: *mut c_void) -> i32 {
    if attr.is_null() { return 22; }
    ensure_default();
    // SAFETY: copy the process-global default attr into the caller's object;
    // attr is a writable pthread_attr_t (>= our Attr size).
    unsafe { *as_attr(attr) = *DEFAULT.0.get(); }
    0
}

// # C: int pthread_setattr_default_np(const pthread_attr_t *attr)
#[no_mangle]
pub unsafe extern "C" fn pthread_setattr_default_np(attr: *const c_void) -> i32 {
    if attr.is_null() { return 22; }
    ensure_default();
    // SAFETY: attr is an initialized pthread_attr_t; validate then copy into
    // the process-global default. A custom stack address is rejected (EINVAL),
    // matching glibc (the default attr must own its stacks).
    unsafe {
        let a = *(attr as *const Attr);
        if a.stackaddr != 0 { return 22; }
        if a.stacksize < MIN_STACK { return 22; }
        *DEFAULT.0.get() = a;
    }
    0
}
