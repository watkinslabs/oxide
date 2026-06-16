// Legacy BSD/SysV signal compat (docs/59§6 G9). sigblock/sigsetmask/sigpause
// (BSD int-mask API over rt_sigprocmask/rt_sigsuspend), siginterrupt
// (toggles SA_RESTART on a handler), sigstack (legacy → sigaltstack),
// sysv_signal (signal() with SysV one-shot semantics), gsignal/ssignal
// (raise/handler-table SysV), psignal ("msg: signame\n" to stderr). All wrap
// the modern sigprocmask/sigaction/sigaltstack already in this crate.
#![cfg(feature = "freestanding")]
use super::sigaction::{sigaction_t, SA_RESTART, SIG_DFL, SIG_IGN};
use super::sigset::sigset_t;
use crate::internal::errno::set as set_errno;

// sigaction/signal/sigprocmask/sigsuspend are #[no_mangle] exports in sibling
// modules (inside private `mod exports`), reachable only as C symbols here.
extern "C" {
    fn sigaction(sig: i32, act: *const sigaction_t, old: *mut sigaction_t) -> i32;
    fn signal(sig: i32, handler: usize) -> usize;
    fn sigprocmask(how: i32, set: *const sigset_t, oldset: *mut sigset_t) -> i32;
    fn sigsuspend(mask: *const sigset_t) -> i32;
}

const EINVAL: i32 = 22;
const SIG_BLOCK: i32 = 0;
const SIG_SETMASK: i32 = 2;
const SIG_ERR: usize = usize::MAX;

// A BSD int-mask is bit (sig-1) of an int; map to/from a sigset_t low word.
fn mask_to_set(mask: i32) -> sigset_t {
    let mut s = sigset_t { __val: [0; 16] };
    s.__val[0] = (mask as u32) as u64;
    s
}

/// # C: int sigblock(int mask) — OR `mask` into the blocked set, return old.
#[no_mangle]
pub unsafe extern "C" fn sigblock(mask: i32) -> i32 {
    // SAFETY: build a sigset_t from the BSD int-mask and SIG_BLOCK it; read the
    // previous mask back from the oldset out-param's low word.
    unsafe {
        let set = mask_to_set(mask);
        let mut old = sigset_t { __val: [0; 16] };
        sigprocmask(SIG_BLOCK, &set, &mut old);
        old.__val[0] as u32 as i32
    }
}

/// # C: int sigsetmask(int mask) — replace the blocked set, return old.
#[no_mangle]
pub unsafe extern "C" fn sigsetmask(mask: i32) -> i32 {
    // SAFETY: SIG_SETMASK the int-mask-derived sigset_t; return the prior mask.
    unsafe {
        let set = mask_to_set(mask);
        let mut old = sigset_t { __val: [0; 16] };
        sigprocmask(SIG_SETMASK, &set, &mut old);
        old.__val[0] as u32 as i32
    }
}

/// # C: int siggetmask(void) — current blocked mask (low word).
#[no_mangle]
pub unsafe extern "C" fn siggetmask() -> i32 {
    // SAFETY: query the current mask via sigblock(0) which ORs nothing.
    unsafe { sigblock(0) }
}

/// # C: int sigpause(int mask) — atomically set mask + suspend (BSD).
#[no_mangle]
pub unsafe extern "C" fn sigpause(mask: i32) -> i32 {
    // SAFETY: suspend with the int-mask-derived sigset_t; rt_sigsuspend always
    // returns -1/EINTR, which is the documented sigpause behaviour.
    unsafe {
        let set = mask_to_set(mask);
        sigsuspend(&set)
    }
}

const SIG_UNBLOCK: i32 = 1;
const SIG_HOLD: usize = 2;

// A one-signal sigset_t (bit sig-1), covering the full 1..64 range.
fn one_sig(sig: i32) -> sigset_t {
    let mut s = sigset_t { __val: [0; 16] };
    if sig >= 1 && sig <= 64 { let n = (sig - 1) as usize; s.__val[n / 64] |= 1u64 << (n % 64); }
    s
}

/// # C: int sighold(int sig) — block `sig` (SysV).
#[no_mangle]
pub unsafe extern "C" fn sighold(sig: i32) -> i32 {
    // SAFETY: SIG_BLOCK a one-signal set via sigprocmask.
    unsafe { let s = one_sig(sig); sigprocmask(SIG_BLOCK, &s, core::ptr::null_mut()) }
}
/// # C: int sigrelse(int sig) — unblock `sig` (SysV).
#[no_mangle]
pub unsafe extern "C" fn sigrelse(sig: i32) -> i32 {
    // SAFETY: SIG_UNBLOCK a one-signal set via sigprocmask.
    unsafe { let s = one_sig(sig); sigprocmask(SIG_UNBLOCK, &s, core::ptr::null_mut()) }
}
/// # C: int sigignore(int sig) — set `sig`'s disposition to SIG_IGN (SysV).
#[no_mangle]
pub unsafe extern "C" fn sigignore(sig: i32) -> i32 {
    // SAFETY: install SIG_IGN for `sig` via sigaction (no flags).
    unsafe {
        let act = sigaction_t { sa_handler: SIG_IGN, sa_mask: sigset_t { __val: [0; 16] }, sa_flags: 0, sa_restorer: 0 };
        sigaction(sig, &act, core::ptr::null_mut())
    }
}
/// # C: sighandler_t sigset(int sig, sighandler_t disp) — SysV set disposition.
/// Returns the previous disposition (SIG_HOLD if the signal was blocked).
#[no_mangle]
pub unsafe extern "C" fn sigset(sig: i32, disp: usize) -> usize {
    // SAFETY: query the prior action + blocked state, then either block the
    // signal (disp==SIG_HOLD) or install the handler and unblock it.
    unsafe {
        let s = one_sig(sig);
        let mut oact = sigaction_t { sa_handler: 0, sa_mask: sigset_t { __val: [0; 16] }, sa_flags: 0, sa_restorer: 0 };
        if sigaction(sig, core::ptr::null(), &mut oact) < 0 { return SIG_ERR; }
        let mut oset = sigset_t { __val: [0; 16] };
        if disp == SIG_HOLD {
            if sigprocmask(SIG_BLOCK, &s, &mut oset) < 0 { return SIG_ERR; }
        } else {
            let act = sigaction_t { sa_handler: disp, sa_mask: sigset_t { __val: [0; 16] }, sa_flags: 0, sa_restorer: 0 };
            if sigaction(sig, &act, core::ptr::null_mut()) < 0 { return SIG_ERR; }
            if sigprocmask(SIG_UNBLOCK, &s, &mut oset) < 0 { return SIG_ERR; }
        }
        let n = (sig - 1) as usize;
        if sig >= 1 && sig <= 64 && (oset.__val[n / 64] >> (n % 64)) & 1 != 0 { SIG_HOLD } else { oact.sa_handler }
    }
}

/// # C: int siginterrupt(int sig, int flag) — toggle SA_RESTART on `sig`.
#[no_mangle]
pub unsafe extern "C" fn siginterrupt(sig: i32, flag: i32) -> i32 {
    // SAFETY: read the current action for `sig`, clear SA_RESTART when flag!=0
    // (interrupt) or set it when flag==0 (restart), write it back.
    unsafe {
        let mut act = sigaction_t { sa_handler: 0, sa_mask: sigset_t { __val: [0; 16] }, sa_flags: 0, sa_restorer: 0 };
        if sigaction(sig, core::ptr::null(), &mut act) < 0 { return -1; }
        if flag != 0 { act.sa_flags &= !SA_RESTART; } else { act.sa_flags |= SA_RESTART; }
        sigaction(sig, &act, core::ptr::null_mut())
    }
}

// struct sigstack (legacy 4.2BSD): { void *ss_sp; int ss_onstack; }.
#[repr(C)]
pub struct sigstack { pub ss_sp: *mut core::ffi::c_void, pub ss_onstack: i32 }

/// # C: int sigstack(struct sigstack *ss, struct sigstack *oss)
#[no_mangle]
pub unsafe extern "C" fn sigstack(_ss: *const sigstack, _oss: *mut sigstack) -> i32 {
    // SAFETY: legacy sigstack lacks a size field; glibc cannot translate it to
    // sigaltstack safely and returns ENOSYS — matching glibc's stub behaviour.
    set_errno(38); // ENOSYS
    -1
}

/// # C: sighandler_t sysv_signal(int sig, sighandler_t handler)
/// SysV signal(): one-shot (no SA_RESTART, no auto-reinstall) — installs the
/// handler with no flags so it resets to SIG_DFL on delivery.
#[no_mangle]
pub unsafe extern "C" fn sysv_signal(sig: i32, handler: usize) -> usize {
    // SAFETY: install `handler` with sa_flags=0 (SysV one-shot); return the
    // previous handler or SIG_ERR. handler may be SIG_DFL/SIG_IGN sentinels.
    unsafe {
        let act = sigaction_t { sa_handler: handler, sa_mask: sigset_t { __val: [0; 16] }, sa_flags: 0, sa_restorer: 0 };
        let mut old = sigaction_t { sa_handler: 0, sa_mask: sigset_t { __val: [0; 16] }, sa_flags: 0, sa_restorer: 0 };
        if sigaction(sig, &act, &mut old) < 0 { return SIG_ERR; }
        old.sa_handler
    }
}

/// # C: sighandler_t bsd_signal(int sig, sighandler_t handler) — BSD signal():
/// SA_RESTART + handler stays installed (== our signal()).
#[no_mangle]
pub unsafe extern "C" fn bsd_signal(sig: i32, handler: usize) -> usize {
    // SAFETY: BSD signal() == our signal(): SA_RESTART, persistent handler.
    unsafe { signal(sig, handler) }
}

// SysV ssignal/gsignal software-signal table: handlers for sig 1..NSIG.
const NSIG: usize = 65;
struct Handlers(core::cell::UnsafeCell<[usize; NSIG]>);
// SAFETY: process-global ssignal/gsignal handler table; single-threaded until
// TLS makes per-thread handlers; matches glibc's global SysV table.
unsafe impl Sync for Handlers {}
static SSIG: Handlers = Handlers(core::cell::UnsafeCell::new([SIG_DFL; NSIG]));

/// # C: sighandler_t ssignal(int sig, sighandler_t action) — set SW handler.
#[no_mangle]
pub unsafe extern "C" fn ssignal(sig: i32, action: usize) -> usize {
    // SAFETY: index the global table by `sig` after range-checking; swap in the
    // new action, returning the previous one (or SIG_ERR if out of range).
    unsafe {
        if sig <= 0 || sig as usize >= NSIG { set_errno(EINVAL); return SIG_ERR; }
        let t = &mut *SSIG.0.get();
        let prev = t[sig as usize];
        t[sig as usize] = action;
        prev
    }
}

/// # C: int gsignal(int sig) — raise a software signal via the ssignal table.
#[no_mangle]
pub unsafe extern "C" fn gsignal(sig: i32) -> i32 {
    // SAFETY: look up the installed SW handler; SIG_DFL → return 0 (SysV: no
    // default action), SIG_IGN → 1, else reset to SIG_DFL and call it.
    unsafe {
        if sig <= 0 || sig as usize >= NSIG { set_errno(EINVAL); return 0; }
        let t = &mut *SSIG.0.get();
        let h = t[sig as usize];
        if h == SIG_DFL { 0 }
        else if h == SIG_IGN { 1 }
        else {
            t[sig as usize] = SIG_DFL;
            let f: extern "C" fn(i32) = core::mem::transmute(h);
            f(sig);
            sig
        }
    }
}

/// # C: void psignal(int sig, const char *s) — print "s: signame\n" to stderr.
#[no_mangle]
pub unsafe extern "C" fn psignal(sig: i32, s: *const u8) {
    // SAFETY: format "<s>: <strsignal(sig)>\n" into a stack buffer and write it
    // to fd 2 with a single write(2). s may be NULL/empty (glibc omits the
    // "<s>: " prefix then). strsignal returns a NUL-terminated 'static or
    // process-global string.
    unsafe {
        let mut buf = [0u8; 96];
        let mut n = 0usize;
        if !s.is_null() {
            let mut p = s;
            while *p != 0 && n < 64 { buf[n] = *p; n += 1; p = p.add(1); }
            if n > 0 { buf[n] = b':'; n += 1; buf[n] = b' '; n += 1; }
        }
        let sig_s = super::desc::strsignal(sig);
        let mut q = sig_s as *const u8;
        while *q != 0 && n < 94 { buf[n] = *q; n += 1; q = q.add(1); }
        buf[n] = b'\n'; n += 1;
        crate::arch::syscall::sys3(crate::internal::nr::WRITE, 2, buf.as_ptr() as usize, n);
    }
}
