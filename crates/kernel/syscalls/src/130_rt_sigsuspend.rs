// 130 rt_sigsuspend — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::validate_user_buf;

/// `sys_rt_sigsuspend(mask, sz)` — slot 130.
/// # C: O(yields until signal)
pub fn sys_rt_sigsuspend(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let mask = args.a0;
    let sz   = args.a1;
    if sz != 8 { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = validate_user_buf(mask, 8, 1) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Eintr.as_i32() as i64),
    };
    // SAFETY: mask validated as a readable 8-byte user sigset_t.
    let m = unsafe { core::ptr::read_unaligned(mask as *const u64) };
    use sched::live::sigpend::Signum;
    let new_mask = m & !(Signum::Sigkill.bit() | Signum::Sigstop.bit());
    let old_mask = cur.sigmask.swap(new_mask, Ordering::AcqRel);
    loop {
        let pending = cur.sigpending.load(Ordering::Acquire);
        if (pending & !cur.sigmask.load(Ordering::Acquire)) != 0 { break; }
        // SAFETY: brief IRQ-on window so timer + IPI signal-raise can land; preempt-off through tick_yield.
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("sti; pause; cli", options(nomem, nostack, preserves_flags)); }
        // SAFETY: process ctx; runqueue installed; preempt-off until tick_yield's Context::switch.
        unsafe { sched::live::tick_yield(); }
    }
    cur.sigmask.store(old_mask, Ordering::Release);
    -(Errno::Eintr.as_i32() as i64)
}
