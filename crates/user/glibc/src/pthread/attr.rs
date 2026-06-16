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
    pub priority: i32,      // sched_param.sched_priority
    pub scope: i32,         // PTHREAD_SCOPE_SYSTEM = 0
    pub guardsize: usize,
    pub stacksize: usize,
    pub stackaddr: usize,   // 0 = libc-allocated
    pub ext: usize,         // 0 or *mut AttrExt (affinity/sigmask), heap-owned
}
// Must overlay inside the smallest host pthread_attr_t (x86_64 = 56 bytes).
const _: () = assert!(core::mem::size_of::<Attr>() <= 56);

// Heap extension for the rarely-used affinity/sigmask attr fields.
#[repr(C)]
pub(crate) struct AttrExt { aff_ptr: usize, aff_size: usize, sigmask: u64, has_sig: i32 }

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
        Attr { detach: 0, inherit: 0, policy: 0, priority: 0, scope: 0, guardsize: PAGE, stacksize: st, stackaddr: 0, ext: 0 }
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
    detach: 0, inherit: 0, policy: 0, priority: 0, scope: 0, guardsize: PAGE, stacksize: 8 << 20, stackaddr: 0, ext: 0,
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
    unsafe { *as_attr(attr) = Attr { detach: 0, inherit: 0, policy: 0, priority: 0, scope: 0, guardsize: PAGE, stacksize: 8 << 20, stackaddr: 0, ext: 0 }; }
    0
}
// # C: int pthread_attr_destroy(pthread_attr_t *attr) — frees the heap ext, if any
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_destroy(attr: *mut c_void) -> i32 {
    // SAFETY: attr is an initialized pthread_attr_t; free its ext block (and the
    // affinity copy) if it was allocated, then clear the pointer.
    unsafe {
        let a = as_attr(attr);
        if (*a).ext != 0 {
            let ext = (*a).ext as *mut AttrExt;
            if (*ext).aff_ptr != 0 { crate::malloc::heap::free((*ext).aff_ptr as *mut u8); }
            crate::malloc::heap::free(ext as *mut u8);
            (*a).ext = 0;
        }
    }
    0
}

// Lazily allocate the attr's heap extension; returns null on OOM.
unsafe fn ext_of(a: *mut Attr) -> *mut AttrExt {
    // SAFETY: a is an initialized Attr; allocate + zero the ext block on first use.
    unsafe {
        if (*a).ext == 0 {
            let e = crate::malloc::heap::malloc(core::mem::size_of::<AttrExt>()) as *mut AttrExt;
            if e.is_null() { return core::ptr::null_mut(); }
            *e = AttrExt { aff_ptr: 0, aff_size: 0, sigmask: 0, has_sig: 0 };
            (*a).ext = e as usize;
        }
        (*a).ext as *mut AttrExt
    }
}

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

// --- sched inherit / policy / param / scope --------------------------------
// # C: int pthread_attr_setinheritsched(pthread_attr_t*, int)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setinheritsched(attr: *mut c_void, inherit: i32) -> i32 {
    if inherit != 0 && inherit != 1 { return 22; }
    // SAFETY: attr is a writable pthread_attr_t; store INHERIT(0)/EXPLICIT(1).
    unsafe { (*as_attr(attr)).inherit = inherit; } 0
}
// # C: int pthread_attr_getinheritsched(const pthread_attr_t*, int*)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getinheritsched(attr: *const c_void, out: *mut i32) -> i32 {
    // SAFETY: attr initialized; out writable int*.
    unsafe { *out = (*(attr as *const Attr)).inherit; } 0
}
// # C: int pthread_attr_setschedpolicy(pthread_attr_t*, int)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setschedpolicy(attr: *mut c_void, policy: i32) -> i32 {
    if policy != 0 && policy != 1 && policy != 2 { return 22; } // OTHER/FIFO/RR
    // SAFETY: attr writable.
    unsafe { (*as_attr(attr)).policy = policy; } 0
}
// # C: int pthread_attr_getschedpolicy(const pthread_attr_t*, int*)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getschedpolicy(attr: *const c_void, out: *mut i32) -> i32 {
    // SAFETY: attr initialized; out writable.
    unsafe { *out = (*(attr as *const Attr)).policy; } 0
}
// # C: int pthread_attr_setschedparam(pthread_attr_t*, const struct sched_param*)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setschedparam(attr: *mut c_void, param: *const i32) -> i32 {
    // SAFETY: param->sched_priority is the first int; copy it into the attr.
    unsafe { (*as_attr(attr)).priority = *param; } 0
}
// # C: int pthread_attr_getschedparam(const pthread_attr_t*, struct sched_param*)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getschedparam(attr: *const c_void, param: *mut i32) -> i32 {
    // SAFETY: param is a writable sched_param; write the stored priority.
    unsafe { *param = (*(attr as *const Attr)).priority; } 0
}
// # C: int pthread_attr_setscope(pthread_attr_t*, int)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setscope(attr: *mut c_void, scope: i32) -> i32 {
    if scope == 1 { return 95; }       // PTHREAD_SCOPE_PROCESS unsupported (ENOTSUP)
    if scope != 0 { return 22; }       // only PTHREAD_SCOPE_SYSTEM(0)
    // SAFETY: attr writable.
    unsafe { (*as_attr(attr)).scope = scope; } 0
}
// # C: int pthread_attr_getscope(const pthread_attr_t*, int*)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getscope(attr: *const c_void, out: *mut i32) -> i32 {
    // SAFETY: attr initialized; out writable.
    unsafe { *out = (*(attr as *const Attr)).scope; } 0
}

// --- stack address/size ----------------------------------------------------
// # C: int pthread_attr_setstack(pthread_attr_t*, void *addr, size_t size)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setstack(attr: *mut c_void, addr: *mut c_void, size: usize) -> i32 {
    if size < MIN_STACK { return 22; }
    // SAFETY: attr writable; record the caller-provided stack region.
    unsafe { let a = as_attr(attr); (*a).stackaddr = addr as usize; (*a).stacksize = size; } 0
}
// # C: int pthread_attr_getstack(const pthread_attr_t*, void **addr, size_t *size)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getstack(attr: *const c_void, addr: *mut usize, size: *mut usize) -> i32 {
    // SAFETY: attr initialized; addr/size writable out-params.
    unsafe { let a = attr as *const Attr; *addr = (*a).stackaddr; *size = (*a).stacksize; } 0
}
// # C: int pthread_attr_setstackaddr(pthread_attr_t*, void*) — deprecated
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setstackaddr(attr: *mut c_void, addr: *mut c_void) -> i32 {
    // SAFETY: attr writable.
    unsafe { (*as_attr(attr)).stackaddr = addr as usize; } 0
}
// # C: int pthread_attr_getstackaddr(const pthread_attr_t*, void**) — deprecated
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getstackaddr(attr: *const c_void, out: *mut usize) -> i32 {
    // SAFETY: attr initialized; out writable.
    unsafe { *out = (*(attr as *const Attr)).stackaddr; } 0
}

// --- affinity (heap ext) ---------------------------------------------------
// # C: int pthread_attr_setaffinity_np(pthread_attr_t*, size_t, const cpu_set_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setaffinity_np(attr: *mut c_void, size: usize, set: *const c_void) -> i32 {
    // SAFETY: set is `size` bytes of cpu_set_t; we copy it into a heap block the
    // attr owns (freed in attr_destroy). size==0 / set==NULL clears affinity.
    unsafe {
        let a = as_attr(attr);
        let ext = ext_of(a);
        if ext.is_null() { return 12; } // ENOMEM
        if (*ext).aff_ptr != 0 { crate::malloc::heap::free((*ext).aff_ptr as *mut u8); (*ext).aff_ptr = 0; (*ext).aff_size = 0; }
        if size == 0 || set.is_null() { return 0; }
        let buf = crate::malloc::heap::malloc(size);
        if buf.is_null() { return 12; }
        core::ptr::copy_nonoverlapping(set as *const u8, buf, size);
        (*ext).aff_ptr = buf as usize; (*ext).aff_size = size;
        0
    }
}
// # C: int pthread_attr_getaffinity_np(const pthread_attr_t*, size_t, cpu_set_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getaffinity_np(attr: *const c_void, size: usize, set: *mut c_void) -> i32 {
    // SAFETY: set is a writable cpu_set_t of `size` bytes. If the attr carries
    // an affinity, copy min(stored,size) and zero the rest; else fill all-ones
    // (glibc: no affinity = every CPU).
    unsafe {
        let a = attr as *const Attr;
        let dst = set as *mut u8;
        if (*a).ext != 0 {
            let ext = (*a).ext as *const AttrExt;
            if (*ext).aff_ptr != 0 {
                let n = core::cmp::min(size, (*ext).aff_size);
                core::ptr::copy_nonoverlapping((*ext).aff_ptr as *const u8, dst, n);
                if size > n { core::ptr::write_bytes(dst.add(n), 0, size - n); }
                return 0;
            }
        }
        core::ptr::write_bytes(dst, 0xff, size);
        0
    }
}

// --- signal mask (heap ext; glibc 2.32+) -----------------------------------
// # C: int pthread_attr_setsigmask_np(pthread_attr_t*, const sigset_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setsigmask_np(attr: *mut c_void, mask: *const c_void) -> i32 {
    // SAFETY: mask is null (clear) or a sigset_t; we store its low kernel word.
    unsafe {
        let ext = ext_of(as_attr(attr));
        if ext.is_null() { return 12; }
        if mask.is_null() { (*ext).has_sig = 0; } else { (*ext).sigmask = *(mask as *const u64); (*ext).has_sig = 1; }
        0
    }
}
// # C: int pthread_attr_getsigmask_np(const pthread_attr_t*, sigset_t*)
// Returns PTHREAD_ATTR_NO_SIGMASK_NP (-1) when no mask is set, else 0.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getsigmask_np(attr: *const c_void, mask: *mut c_void) -> i32 {
    // SAFETY: mask is a writable sigset_t; write the stored low word + zero rest.
    unsafe {
        let a = attr as *const Attr;
        if (*a).ext != 0 {
            let ext = (*a).ext as *const AttrExt;
            if (*ext).has_sig != 0 {
                core::ptr::write_bytes(mask as *mut u8, 0, 8);
                *(mask as *mut u64) = (*ext).sigmask;
                return 0;
            }
        }
        -1 // PTHREAD_ATTR_NO_SIGMASK_NP
    }
}
