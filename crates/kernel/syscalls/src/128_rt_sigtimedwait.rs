// 128 rt_sigtimedwait — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_rt_sigtimedwait(set, info, timeout, sz)` — slot 128.
/// # C: O(yields until signal or timeout)
pub fn sys_rt_sigtimedwait(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use hal::TimerOps;
    use syscall::errno::Errno;
    let set     = args.a0;
    let info    = args.a1;
    let timeout = args.a2;
    let sz      = args.a3;
    debug_ssh! {
        klog::write_raw(b"[INFO]  ssh-trace: rt_sigtimedwait set_ptr=");
        klog::write_hex_u64(set);
        klog::write_raw(b" timeout_ptr=");
        klog::write_hex_u64(timeout);
        klog::write_raw(b"\n");
    }
    if sz != 8 { return -(Errno::Einval.as_i32() as i64); }
    if set == 0 || set >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: set validated < USER_VA_END; CPL=0 reads via active CR3.
    let wanted = unsafe { core::ptr::read_volatile(set as *const u64) };
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Eintr.as_i32() as i64),
    };
    let deadline = if timeout != 0 && timeout < hal::USER_VA_END {
        // SAFETY: timeout validated < USER_VA_END; struct timespec layout {tv_sec, tv_nsec}; CPL=0 reads.
        let secs = unsafe { core::ptr::read_volatile(timeout as *const i64) };
        // SAFETY: timeout+8 inside the 16-byte timespec; aligned i64 read.
        let nsec = unsafe { core::ptr::read_volatile((timeout + 8) as *const i64) };
        if secs < 0 || nsec < 0 || nsec >= 1_000_000_000 {
            return -(Errno::Einval.as_i32() as i64);
        }
        let total = (secs as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64);
        #[cfg(target_arch = "x86_64")]
        let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
        #[cfg(target_arch = "aarch64")]
        let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        Some(now.saturating_add(total))
    } else { None };
    loop {
        let pending = cur.sigpending.load(Ordering::Acquire);
        let arrived = pending & wanted;
        if arrived != 0 {
            let sig = arrived.trailing_zeros() + 1;
            let popped: Option<sched::SigInfo> = if sig >= 33 && sig <= 64 {
                let (rec, empty) = cur.rt_pop(sig);
                if empty {
                    cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
                }
                rec
            } else {
                cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
                None
            };
            if info != 0 && info < hal::USER_VA_END {
                // SAFETY: info validated < USER_VA_END; siginfo_t is 128 bytes; CPL=0 writes through caller's AS.
                unsafe {
                    for i in 0..128usize {
                        core::ptr::write_volatile((info + i as u64) as *mut u8, 0);
                    }
                    core::ptr::write_volatile(info as *mut i32, sig as i32);
                    if let Some(rec) = popped {
                        // si_errno=0; si_code at +8; si_pid at +16; si_uid at +20; si_value at +24.
                        core::ptr::write_volatile((info +  8) as *mut i32, rec.code);
                        core::ptr::write_volatile((info + 16) as *mut u32, rec.pid);
                        core::ptr::write_volatile((info + 20) as *mut u32, rec.uid);
                        core::ptr::write_volatile((info + 24) as *mut u64, rec.value);
                    }
                }
            }
            return sig as i64;
        }
        if let Some(dl) = deadline {
            #[cfg(target_arch = "x86_64")]
            let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
            #[cfg(target_arch = "aarch64")]
            let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
            if now >= dl { return -(Errno::Eagain.as_i32() as i64); }
        }
        // SAFETY: brief IRQ-on window so timer + IPI signal-raise can land; preempt-off through tick_yield.
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("sti; pause; cli", options(nomem, nostack, preserves_flags)); }
        // SAFETY: process ctx; runqueue installed; preempt-off until tick_yield's Context::switch.
        unsafe { sched::live::tick_yield(); }
    }
}
