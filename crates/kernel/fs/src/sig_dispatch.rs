// Signal-handler dispatch per docs/27§5. ARCH-NEUTRAL orchestration only:
// this file owns the sigmask blocking (sched) and routes to the per-arch
// signal-frame builder/restorer in the HAL crates (`hal_x86_64::signal`,
// `hal_aarch64::signal`). The arch-specific Linux `rt_sigframe` layout +
// register save/restore lives in those crates (docs/52, docs/20 HAL
// boundary) — NOT #[cfg]-gated here.
//
// The full Linux rt_sigframe (siginfo_t + ucontext_t with the full register
// set) is built, so SA_SIGINFO handlers (the Go runtime, glibc/musl crash
// handlers, profilers) are invoked `handler(sig, &siginfo, &ucontext)` and
// rt_sigreturn restores the full register set (not just rip/rsp/rflags).

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

/// Arch-neutral signal delivery: block the signal, then route to the per-arch
/// frame builder. Returns `sig` on aarch64 (the dispatch retval seeds user x0
/// = the handler's first AAPCS64 arg, since the SVC restore loads x0 from the
/// retval slot, docs/54 §2.3); x86_64 ignores the return (rdi is seeded via
/// the saved slot).
/// # SAFETY: caller is the syscall dispatch tail on the running task's
/// per-task kernel stack; the per-arch saved frame is live; active CR3/TTBR0
/// is the running task's user AS.
/// # C: O(1)
#[inline]
pub unsafe fn deliver(handler: u64, restorer: u64, sig: u32, saved_ret: u64) -> u64 {
    // Block the delivered signal during its handler (POSIX SA_NODEFER-off);
    // rt_sigreturn restores this mask (docs/54 §3.5).
    let old_sigmask = match sched::live::current() {
        Some(c) => c.sigmask.fetch_or(1u64 << (sig - 1), Ordering::AcqRel),
        None    => 0,
    };
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: dispatch tail; hal owns the arch frame mechanics + uses the
        // live saved syscall frame on this CPU's kstack.
        unsafe { hal_x86_64::build_signal_frame(handler, restorer, sig, saved_ret, old_sigmask); }
        0
    }
    #[cfg(target_arch = "aarch64")]
    {
        // F206: prefer the per-task SVC-frame slot (race-free vs schedule());
        // fall back to the per-CPU current frame for slot-less tasks.
        let frame = sched::live::current()
            .map(|c| c.svc_frame.load(Ordering::Acquire))
            .filter(|p| *p != 0)
            .map(|p| p as *mut hal_aarch64::SvcFrame)
            .unwrap_or_else(hal_aarch64::current_svc_frame);
        // SAFETY: dispatch tail; `frame` is the live saved SVC frame.
        unsafe { hal_aarch64::build_signal_frame(frame, handler, restorer, sig, saved_ret, old_sigmask); }
        sig as u64
    }
}

/// Arch-neutral `rt_sigreturn` body: route to the per-arch restorer, store the
/// restored sigmask, and return the interrupted syscall's retval (becomes user
/// rax/x0 after the dispatch epilogue). EINVAL on a malformed frame.
/// # SAFETY: caller is the rt_sigreturn syscall dispatch on the running task's
/// per-task kernel stack; the per-arch saved frame is live.
/// # C: O(1)
#[inline]
pub unsafe fn rt_sigreturn() -> i64 {
    use syscall::errno::Errno;
    #[cfg(target_arch = "x86_64")]
    // SAFETY: rt_sigreturn dispatch tail; hal owns the arch restore.
    let restored = unsafe { hal_x86_64::restore_signal_frame() };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: rt_sigreturn dispatch tail; live saved SVC frame on this CPU.
    let restored = unsafe { hal_aarch64::restore_signal_frame(hal_aarch64::current_svc_frame()) };
    match restored {
        Some((sigmask, ret)) => {
            if let Some(c) = sched::live::current() {
                c.sigmask.store(sigmask, Ordering::Release);
            }
            ret
        }
        None => -(Errno::Einval.as_i32() as i64),
    }
}
