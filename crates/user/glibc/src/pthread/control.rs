// pthread thread-control + scheduling (docs/59§6 G11/§9.1). All syscall-backed
// against the target thread's kernel tid (pthread_t is the TCB pointer; tid is
// in the TCB). pthread_* return the errno DIRECTLY (0 ok, positive errno),
// never -1/errno.
#![cfg(feature = "freestanding")]
use core::ffi::{c_char, c_void};
use core::sync::atomic::{AtomicI32, Ordering};
use crate::arch::syscall::{sys2, sys3, sys4};
use crate::internal::nr;
use crate::posix::ids::gettid;
use crate::posix::io::getpid;

// errno-direct result: 0 on success, positive errno on failure.
fn e(r: isize) -> i32 { if r < 0 { -r as i32 } else { 0 } }

// tid stored in the TCB (pthread_t == *mut Tcb).
unsafe fn tid_of(thread: usize) -> i32 {
    // SAFETY: thread is a live pthread_t (TCB pointer) from pthread_create or
    // pthread_self; we read the tid word the kernel set via PARENT_SETTID.
    unsafe { (*(thread as *mut super::Tcb)).tid }
}

// # C: int pthread_kill(pthread_t thread, int sig)
#[no_mangle]
pub unsafe extern "C" fn pthread_kill(thread: usize, sig: i32) -> i32 {
    // SAFETY: tgkill(tgid, tid, sig) targets one thread of this process.
    unsafe { e(sys3(nr::TGKILL, getpid() as usize, tid_of(thread) as usize, sig as usize)) }
}

// # C: int pthread_sigqueue(pthread_t thread, int sig, const union sigval value)
#[no_mangle]
pub unsafe extern "C" fn pthread_sigqueue(thread: usize, sig: i32, value: usize) -> i32 {
    const SI_QUEUE: i32 = -1;
    // SAFETY: a 128-byte siginfo_t scratch on this frame filled with the kernel
    // _rt layout (signo@0, code@8, pid@16, uid@20, sigval@24), passed to
    // rt_tgsigqueueinfo for the target tid.
    unsafe {
        let tid = tid_of(thread);
        let mut info = [0u8; 128];
        let p = info.as_mut_ptr();
        *(p.add(0) as *mut i32) = sig;
        *(p.add(8) as *mut i32) = SI_QUEUE;
        *(p.add(16) as *mut i32) = getpid();
        *(p.add(20) as *mut u32) = crate::posix::ids::getuid();
        *(p.add(24) as *mut usize) = value;
        e(sys4(nr::RT_TGSIGQUEUEINFO, getpid() as usize, tid as usize, sig as usize, p as usize))
    }
}

// # C: int pthread_getcpuclockid(pthread_t thread, clockid_t *clockid)
#[no_mangle]
pub unsafe extern "C" fn pthread_getcpuclockid(thread: usize, clockid: *mut i32) -> i32 {
    // SAFETY: clockid is a writable clockid_t; we encode the per-thread CPU
    // clock id the kernel posix-cpu-timers expects: (~tid<<3)|SCHED|PERTHREAD.
    unsafe {
        let tid = tid_of(thread);
        *clockid = (!tid << 3) | 2 /* CPUCLOCK_SCHED */ | 4 /* PERTHREAD */;
        0
    }
}

// # C: int pthread_setschedparam(pthread_t, int policy, const struct sched_param*)
#[no_mangle]
pub unsafe extern "C" fn pthread_setschedparam(thread: usize, policy: i32, param: *const c_void) -> i32 {
    // SAFETY: param is a struct sched_param the kernel reads for the target tid.
    unsafe { e(sys3(nr::SCHED_SETSCHEDULER, tid_of(thread) as usize, policy as usize, param as usize)) }
}

// # C: int pthread_getschedparam(pthread_t, int *policy, struct sched_param*)
#[no_mangle]
pub unsafe extern "C" fn pthread_getschedparam(thread: usize, policy: *mut i32, param: *mut c_void) -> i32 {
    // SAFETY: policy/param are writable out-params; sched_getscheduler returns
    // the policy, sched_getparam fills the priority.
    unsafe {
        let tid = tid_of(thread);
        let pol = sys2(nr::SCHED_GETSCHEDULER, tid as usize, 0);
        if pol < 0 { return -pol as i32; }
        if !policy.is_null() { *policy = pol as i32; }
        e(sys2(nr::SCHED_GETPARAM, tid as usize, param as usize))
    }
}

// # C: int pthread_setschedprio(pthread_t thread, int prio)
#[no_mangle]
pub unsafe extern "C" fn pthread_setschedprio(thread: usize, prio: i32) -> i32 {
    // SAFETY: keep the current policy (sched_getscheduler) and set only the
    // priority via sched_setscheduler with a local sched_param on this frame.
    unsafe {
        let tid = tid_of(thread);
        let pol = sys2(nr::SCHED_GETSCHEDULER, tid as usize, 0);
        if pol < 0 { return -pol as i32; }
        let param = [prio]; // struct sched_param { int sched_priority; }
        e(sys3(nr::SCHED_SETSCHEDULER, tid as usize, pol as usize, param.as_ptr() as usize))
    }
}

// # C: int pthread_setaffinity_np(pthread_t, size_t cpusetsize, const cpu_set_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_setaffinity_np(thread: usize, size: usize, set: *const c_void) -> i32 {
    // SAFETY: set is a cpu_set_t of `size` bytes the kernel reads for the tid.
    unsafe { e(sys3(nr::SCHED_SETAFFINITY, tid_of(thread) as usize, size, set as usize)) }
}

// # C: int pthread_getaffinity_np(pthread_t, size_t cpusetsize, cpu_set_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_getaffinity_np(thread: usize, size: usize, set: *mut c_void) -> i32 {
    // SAFETY: set is a writable cpu_set_t of `size` bytes the kernel fills; the
    // kernel returns the bytes written (>=0) on success → 0 to the caller.
    unsafe { e(sys3(nr::SCHED_GETAFFINITY, tid_of(thread) as usize, size, set as usize)) }
}

// # C: int pthread_setname_np(pthread_t thread, const char *name)
// glibc: PR_SET_NAME for self, /proc/self/task/<tid>/comm otherwise. Max 16
// bytes incl NUL → ERANGE.
#[no_mangle]
pub unsafe extern "C" fn pthread_setname_np(thread: usize, name: *const c_char) -> i32 {
    const PR_SET_NAME: usize = 15;
    const ERANGE: i32 = 34;
    // SAFETY: name is a NUL-terminated string ≤16 bytes; for self we prctl,
    // else write the comm file for the target tid.
    unsafe {
        let n = crate::string::len::strlen_impl(name as *mut u8);
        if n >= 16 { return ERANGE; }
        let tid = tid_of(thread);
        if tid == gettid() {
            return e(sys2(nr::PRCTL, PR_SET_NAME, name as usize));
        }
        comm_io(tid, name as *mut u8, n, true)
    }
}

// # C: int pthread_getname_np(pthread_t thread, char *buf, size_t len)
#[no_mangle]
pub unsafe extern "C" fn pthread_getname_np(thread: usize, buf: *mut c_char, len: usize) -> i32 {
    const PR_GET_NAME: usize = 16;
    const ERANGE: i32 = 34;
    // SAFETY: buf is writable for `len` bytes; PR_GET_NAME needs ≥16. For self
    // prctl fills buf directly; else read the comm file.
    unsafe {
        if len < 16 { return ERANGE; }
        let tid = tid_of(thread);
        if tid == gettid() {
            return e(sys2(nr::PRCTL, PR_GET_NAME, buf as usize));
        }
        comm_io(tid, buf as *mut u8, 0, false)
    }
}

// Read/write /proc/self/task/<tid>/comm. write=true sets the name (n bytes);
// write=false reads up to 15 bytes into buf, NUL-terminates, strips newline.
unsafe fn comm_io(tid: i32, buf: *mut u8, n: usize, write: bool) -> i32 {
    // SAFETY: builds the comm path on this frame, opens it, and reads/writes
    // through the caller's buffer; all pointers stay in-bounds.
    unsafe {
        let mut path = [0u8; 40];
        let pre = b"/proc/self/task/";
        let mut i = 0;
        while i < pre.len() { path[i] = pre[i]; i += 1; }
        i += fmt_u32(tid as u32, path.as_mut_ptr().add(i));
        let suf = b"/comm\0";
        let mut j = 0;
        while j < suf.len() { path[i + j] = suf[j]; j += 1; }
        let flags = if write { 1 /* O_WRONLY */ } else { 0 /* O_RDONLY */ };
        let fd = crate::posix::io::open(path.as_ptr(), flags, 0);
        if fd < 0 { return -fd; }
        let r = if write {
            crate::arch::syscall::sys3(nr::WRITE, fd as usize, buf as usize, n)
        } else {
            let g = crate::arch::syscall::sys3(nr::READ, fd as usize, buf as usize, 15);
            if g > 0 {
                let mut k = g as usize;
                if k > 0 && *buf.add(k - 1) == b'\n' { k -= 1; }
                *buf.add(k) = 0;
            }
            g
        };
        crate::posix::io::close(fd);
        e(r)
    }
}

// Minimal u32→decimal into out; returns digit count. No NUL.
unsafe fn fmt_u32(mut v: u32, out: *mut u8) -> usize {
    // SAFETY: out has room for ≤10 digits; we write the decimal representation.
    unsafe {
        if v == 0 { *out = b'0'; return 1; }
        let mut tmp = [0u8; 10];
        let mut k = 0;
        while v > 0 { tmp[k] = b'0' + (v % 10) as u8; v /= 10; k += 1; }
        for m in 0..k { *out.add(m) = tmp[k - 1 - m]; }
        k
    }
}

// # C: int sched_yield(void) / int pthread_yield(void)
#[no_mangle]
pub unsafe extern "C" fn pthread_yield() -> i32 {
    // SAFETY: sched_yield(2) takes no args; returns 0 or -1/errno.
    unsafe { crate::internal::errno::ret_isize(crate::arch::syscall::sys0(nr::SCHED_YIELD)) as i32 }
}

// # C: void pthread_kill_other_threads_np(void) — NPTL no-op (LinuxThreads relic).
#[no_mangle]
pub extern "C" fn pthread_kill_other_threads_np() {}

// --- cancellation (deferred; acts at testcancel / cancellation points) -----
use super::{current_tcb, join_common, Tcb};
const PTHREAD_CANCELED: *mut c_void = usize::MAX as *mut c_void;

// # C: int pthread_setcancelstate(int state, int *oldstate)
#[no_mangle]
pub unsafe extern "C" fn pthread_setcancelstate(state: i32, oldstate: *mut i32) -> i32 {
    if state != 0 && state != 1 { return 22; } // ENABLE(0)/DISABLE(1)
    // SAFETY: current_tcb is valid on any thread once the TCB is installed;
    // oldstate is null or a writable int receiving the prior state.
    unsafe {
        let tcb = current_tcb();
        if !oldstate.is_null() { *oldstate = (*tcb).cancelstate; }
        (*tcb).cancelstate = state;
    }
    0
}
// # C: int pthread_setcanceltype(int type, int *oldtype)
#[no_mangle]
pub unsafe extern "C" fn pthread_setcanceltype(ty: i32, oldtype: *mut i32) -> i32 {
    if ty != 0 && ty != 1 { return 22; } // DEFERRED(0)/ASYNCHRONOUS(1)
    // SAFETY: as setcancelstate; updates this thread's TCB cancel type.
    unsafe {
        let tcb = current_tcb();
        if !oldtype.is_null() { *oldtype = (*tcb).canceltype; }
        (*tcb).canceltype = ty;
    }
    0
}
// # C: void pthread_testcancel(void)
#[no_mangle]
pub unsafe extern "C" fn pthread_testcancel() {
    // SAFETY: if a cancel is pending and cancellation is enabled, terminate this
    // thread with PTHREAD_CANCELED (the deferred-cancellation contract).
    unsafe {
        let tcb = current_tcb();
        if (*tcb).cancelreq != 0 && (*tcb).cancelstate == 0 {
            crate::pthread::pthread_exit(PTHREAD_CANCELED);
        }
    }
}
// # C: int pthread_cancel(pthread_t thread)
#[no_mangle]
pub unsafe extern "C" fn pthread_cancel(thread: usize) -> i32 {
    // SAFETY: thread is a live pthread_t; set its cancel-requested flag. If the
    // target is the caller and asynchronous+enabled, act immediately.
    unsafe {
        let tcb = thread as *mut Tcb;
        (*tcb).cancelreq = 1;
        if thread == current_tcb() as usize && (*tcb).canceltype == 1 && (*tcb).cancelstate == 0 {
            crate::pthread::pthread_exit(PTHREAD_CANCELED);
        }
    }
    0
}

// --- timed / try join + getattr_np -----------------------------------------
// # C: int pthread_tryjoin_np(pthread_t, void **retval)
#[no_mangle]
pub unsafe extern "C" fn pthread_tryjoin_np(thread: usize, retval: *mut *mut c_void) -> i32 {
    // SAFETY: thread is a joinable pthread_t; non-blocking reap or EBUSY.
    unsafe { join_common(thread, retval, 1, 0, core::ptr::null()) }
}
// # C: int pthread_timedjoin_np(pthread_t, void **retval, const struct timespec *abstime)
#[no_mangle]
pub unsafe extern "C" fn pthread_timedjoin_np(thread: usize, retval: *mut *mut c_void, abstime: *const crate::time::clock::timespec) -> i32 {
    // SAFETY: abstime is an absolute CLOCK_REALTIME deadline.
    unsafe { join_common(thread, retval, 2, 0 /* CLOCK_REALTIME */, abstime) }
}
// # C: int pthread_clockjoin_np(pthread_t, void **retval, clockid_t, const struct timespec *abstime)
#[no_mangle]
pub unsafe extern "C" fn pthread_clockjoin_np(thread: usize, retval: *mut *mut c_void, clk: i32, abstime: *const crate::time::clock::timespec) -> i32 {
    // SAFETY: abstime is an absolute deadline on `clk`.
    unsafe { join_common(thread, retval, 2, clk, abstime) }
}

// # C: int pthread_getattr_np(pthread_t thread, pthread_attr_t *attr)
// Fill attr from the thread's actual stack region (created threads carry it in
// the TCB; the main thread's size comes from RLIMIT_STACK).
#[no_mangle]
pub unsafe extern "C" fn pthread_getattr_np(thread: usize, attr: *mut c_void) -> i32 {
    use crate::pthread::attr::Attr;
    // SAFETY: thread is a live pthread_t; attr is a writable pthread_attr_t we
    // overlay our Attr onto and populate with the thread's stack + guardsize.
    unsafe {
        let tcb = thread as *const Tcb;
        let (base, size) = ((*tcb).stack_base, (*tcb).stack_size);
        let a = attr as *mut Attr;
        (*a).detach = 0; (*a).inherit = 0; (*a).policy = 0; (*a).priority = 0;
        (*a).scope = 0; (*a).guardsize = 4096; (*a).ext = 0;
        if base != 0 {
            (*a).stackaddr = base; (*a).stacksize = size;
        } else {
            // main thread: size from RLIMIT_STACK, address unknown (0)
            let mut rl = crate::posix::resource::Rlimit { rlim_cur: 0, rlim_max: 0 };
            let r = crate::posix::resource::getrlimit(3 /* RLIMIT_STACK */, &mut rl);
            (*a).stacksize = if r == 0 && rl.rlim_cur != crate::posix::resource::RLIM_INFINITY { rl.rlim_cur as usize } else { 8 << 20 };
            (*a).stackaddr = 0;
        }
        0
    }
}

static CONCURRENCY: AtomicI32 = AtomicI32::new(0);
// # C: int pthread_getconcurrency(void)
#[no_mangle]
pub extern "C" fn pthread_getconcurrency() -> i32 { CONCURRENCY.load(Ordering::Relaxed) }
// # C: int pthread_setconcurrency(int level)
#[no_mangle]
pub extern "C" fn pthread_setconcurrency(level: i32) -> i32 {
    if level < 0 { return 22; } // EINVAL
    CONCURRENCY.store(level, Ordering::Relaxed);
    0
}
