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
pub unsafe fn deliver(handler: u64, restorer: u64, sig: u32, saved_ret: u64, restart: bool) -> u64 {
    // SAFETY: no extra siginfo payload (e.g. SIGILL from ptrace) —
    // pass-through to the siginfo-aware variant with `None`.
    unsafe { deliver_with_info(handler, restorer, sig, saved_ret, restart, None) }
}

/// B117: `deliver` variant that threads the extra SA_SIGINFO payload
/// (`hal::SigChld` for SIGCHLD) into the per-arch frame builder so an
/// SA_SIGINFO handler reads si_pid/si_status/si_code. `None` ⇒ a
/// signo-only siginfo (prior behaviour).
/// # SAFETY: same contract as `deliver`.
/// # C: O(1)
#[inline]
pub unsafe fn deliver_with_info(handler: u64, restorer: u64, sig: u32, saved_ret: u64, restart: bool,
                                chld: Option<hal::SigChld>) -> u64 {
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
        unsafe { hal_x86_64::build_signal_frame(handler, restorer, sig, saved_ret, restart, old_sigmask, chld); }
        0
    }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = restorer; // AArch64 uses the mm-owned vDSO entry below.
        // Linux arm64 owns the restorer in the mapped vDSO. AArch64 glibc
        // intentionally leaves sa_restorer zero, unlike x86_64.
        let restorer = sched::live::current()
            // SAFETY: current task's mm is stable for this dispatch tail.
            .and_then(|c| unsafe { c.mm_ref() })
            .map(|mm| mm.vdso_rt_sigreturn())
            .filter(|v| *v != 0)
            .unwrap_or_else(|| sched::live::terminate_current_with_signal(sched::live::Signum::Sigsegv.as_u8()));
        // F206: prefer the per-task SVC-frame slot (race-free vs schedule());
        // fall back to the per-CPU current frame for slot-less tasks.
        let frame = sched::live::current()
            .map(|c| c.svc_frame.load(Ordering::Acquire))
            .filter(|p| *p != 0)
            .map(|p| p as *mut hal_aarch64::SvcFrame)
            .unwrap_or_else(hal_aarch64::current_svc_frame);
        // SAFETY: dispatch tail; `frame` is the live saved SVC frame.
        unsafe { hal_aarch64::build_signal_frame(frame, handler, restorer, sig, saved_ret, restart, old_sigmask, chld); }
        sig as u64
    }
}

/// Arch-neutral `rt_sigreturn` body: route to the per-arch restorer, store the
/// restored sigmask, and return the interrupted syscall's retval (becomes user
/// rax/x0 after the dispatch epilogue). Malformed frames force SIGSEGV.
/// # SAFETY: caller is the rt_sigreturn syscall dispatch on the running task's
/// per-task kernel stack; the per-arch saved frame is live.
/// # C: O(1)
#[inline]
pub unsafe fn rt_sigreturn() -> i64 {
    #[cfg(target_arch = "x86_64")]
    {
        let Some((ptr, len, align)) = hal_x86_64::rt_sigreturn_frame_range() else {
            return bad_rt_sigframe();
        };
        if crate::userbuf::validate_user_buf_readable(ptr, len, align).is_err() {
            return bad_rt_sigframe();
        }
    }
    #[cfg(target_arch = "aarch64")]
    let frame = current_signal_svc_frame();
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: rt_sigreturn dispatch tail; `frame` is the live saved SVC frame.
        let Some((ptr, len, align)) = (unsafe { hal_aarch64::rt_sigreturn_frame_range(frame) }) else {
            return bad_rt_sigframe();
        };
        if crate::userbuf::validate_user_buf_readable(ptr, len, align).is_err() {
            return bad_rt_sigframe();
        }
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: rt_sigreturn dispatch tail; hal owns the arch restore.
    let restored = unsafe { hal_x86_64::restore_signal_frame() };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: rt_sigreturn dispatch tail; `frame` is the live saved SVC frame.
    let restored = unsafe { hal_aarch64::restore_signal_frame(frame) };
    match restored {
        Some((sigmask, ret)) => {
            if let Some(c) = sched::live::current() {
                c.set_current_blocked(sigmask);
            }
            ret
        }
        None => sched::live::terminate_current_with_signal(sched::live::Signum::Sigsegv.as_u8()),
    }
}

#[inline]
fn bad_rt_sigframe() -> i64 {
    sched::live::terminate_current_with_signal(sched::live::Signum::Sigsegv.as_u8())
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn current_signal_svc_frame() -> *mut hal_aarch64::SvcFrame {
    sched::live::current()
        .map(|c| c.svc_frame.load(Ordering::Acquire))
        .filter(|p| *p != 0)
        .map(|p| p as *mut hal_aarch64::SvcFrame)
        .unwrap_or_else(hal_aarch64::current_svc_frame)
}
