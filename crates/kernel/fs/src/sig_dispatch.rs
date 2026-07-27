// Signal-handler dispatch per docs/27§5. ARCH-NEUTRAL orchestration only:
// this file owns the sigmask blocking + alternate-stack selection (sched) and
// routes to the per-arch signal-frame builder/restorer in the HAL crates
// (`hal_x86_64::signal`, `hal_aarch64::signal`). The arch-specific Linux
// `rt_sigframe` layout + register save/restore lives in those crates
// (docs/52, docs/20 HAL boundary) — NOT #[cfg]-gated here.
//
// The full Linux rt_sigframe (siginfo_t + ucontext_t with the full register
// set) is built, so SA_SIGINFO handlers (the Go runtime, glibc/musl crash
// handlers, profilers) are invoked `handler(sig, &siginfo, &ucontext)` and
// rt_sigreturn restores the full register set (not just rip/rsp/rflags).

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;
use sched::sigaltstack as sas;

/// Linux `SA_NODEFER` — do not add the delivered signal to the handler's
/// blocked mask.
const SA_NODEFER: u64 = 0x4000_0000;
/// Linux `SA_ONSTACK` — run the handler on the `sigaltstack(2)` stack.
const SA_ONSTACK: u64 = 0x0800_0000;

/// The interrupted task's user stack pointer (Linux
/// `current_user_stack_pointer()`). Sole arch boundary for that read, shared
/// by signal delivery and `sigaltstack(2)` so the two can never disagree about
/// whether the caller is standing on the alternate stack.
/// # C: O(1)
pub fn current_user_sp() -> u64 {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: syscall/dispatch tail on the running task's kstack; the saved
    // frame is live and exclusively owned here.
    unsafe { hal_x86_64::current_user_sp() }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: same dispatch-tail contract; `current_signal_svc_frame` resolves
    // the running task's live SVC frame.
    unsafe { hal_aarch64::svc_frame_user_sp(current_signal_svc_frame()) }
}

/// Arch-neutral signal delivery: pick the handler stack, compute the mask the
/// frame records and the mask the handler runs under, then route to the
/// per-arch frame builder. Returns `sig` on aarch64 (the dispatch retval seeds
/// user x0 = the handler's first AAPCS64 arg, since the SVC restore loads x0
/// from the retval slot, docs/54 §2.3); x86_64 ignores the return (rdi is
/// seeded via the saved slot).
///
/// `payload` is the SA_SIGINFO siginfo an `SA_SIGINFO` handler reads;
/// `sa_flags`/`sa_mask` are the installed `sigaction(2)` state Linux's
/// `handle_signal` consumes (SA_ONSTACK, SA_NODEFER, the handler's hold-off
/// mask). The ONE entry point — a variant that dropped the flags would deliver
/// signals that silently ignore SA_ONSTACK and `sa_mask`.
/// # SAFETY: caller is the syscall dispatch tail on the running task's
/// per-task kernel stack; the per-arch saved frame is live; active CR3/TTBR0
/// is the running task's user AS.
/// # C: O(1)
#[inline]
pub unsafe fn deliver_with_info(handler: u64, restorer: u64, sig: u32, saved_ret: u64, restart: bool,
                                payload: Option<hal::SigPayload>, sa_flags: u64, sa_mask: u64) -> u64 {
    let user_sp = current_user_sp();
    let (frame_mask, alt) = match sched::live::current() {
        Some(c) => (setup_masks(&c, sig, sa_flags, sa_mask), setup_altstack(&c, user_sp, sa_flags)),
        None    => (0, hal::AltStack::default()),
    };
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: dispatch tail; hal owns the arch frame mechanics + uses the
        // live saved syscall frame on this CPU's kstack.
        unsafe { hal_x86_64::build_signal_frame(handler, restorer, sig, saved_ret, restart, frame_mask, payload, alt); }
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
        let frame = current_signal_svc_frame();
        // SAFETY: dispatch tail; `frame` is the live saved SVC frame.
        unsafe { hal_aarch64::build_signal_frame(frame, handler, restorer, sig, saved_ret, restart, frame_mask, payload, alt); }
        sig as u64
    }
}

/// Linux `sigmask_to_save()` + `signal_delivered()`. Returns the mask the
/// signal frame records (what `rt_sigreturn` will restore) and installs the
/// mask the handler runs under.
///
/// The frame gets the SAVED mask whenever `rt_sigsuspend`/`pselect6` armed one
/// — that is the whole point of `TIF_RESTORE_SIGMASK`: the handler runs with
/// the suspend mask, and `sigreturn` drops back to the caller's original one.
/// The handler's mask is the live mask OR `sa_mask` OR (unless SA_NODEFER) the
/// signal itself, so `sigaction(2)`'s promised hold-off is real.
/// # C: O(1)
fn setup_masks(cur: &sched::Task, sig: u32, sa_flags: u64, sa_mask: u64) -> u64 {
    let frame_mask = cur.sigmask_to_save();
    let mut blocked = cur.sigmask.load(Ordering::Acquire) | sa_mask;
    if sa_flags & SA_NODEFER == 0 {
        if let Some(bit) = sched::signum::bit_for(sig) { blocked |= bit; }
    }
    cur.set_current_blocked(blocked);
    frame_mask
}

/// Linux `sigsp()` + `save_altstack_ex()` + the `SS_AUTODISARM` half of
/// `signal_delivered`. Decides whether this delivery switches to the
/// alternate stack, hands the arch builder the `uc_stack` contents
/// `rt_sigreturn` will restore, and disarms an `SS_AUTODISARM` stack for the
/// duration of the handler.
/// # C: O(1)
fn setup_altstack(cur: &sched::Task, user_sp: u64, sa_flags: u64) -> hal::AltStack {
    let cur_alt = cur.altstack();
    let use_alt = sas::use_alt_stack(user_sp, cur_alt, sa_flags & SA_ONSTACK != 0);
    let out = hal::AltStack {
        sp:      cur_alt.sp,
        size:    cur_alt.size,
        // `uc_stack.ss_flags` is what `sigaltstack(2)` would report right now,
        // so `restore_altstack` at sigreturn re-arms the same state.
        flags:   sas::sas_ss_flags(user_sp, cur_alt),
        use_alt,
    };
    // `signal_delivered`: `if (current->sas_ss_flags & SS_AUTODISARM)
    // sas_ss_reset(current);` — unconditional on whether this delivery
    // actually switched stacks, so an armed SS_AUTODISARM stack is disarmed by
    // ANY successful delivery and re-armed from `uc_stack` at sigreturn.
    if cur_alt.flags & sas::SS_AUTODISARM != 0 {
        cur.set_altstack(sas::reset());
    }
    out
}

/// Arch-neutral `rt_sigreturn` body: route to the per-arch restorer, store the
/// restored sigmask, re-arm the alternate stack from `uc_stack`, and return
/// the interrupted syscall's retval (becomes user rax/x0 after the dispatch
/// epilogue). Malformed frames force SIGSEGV.
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
        Some((sigmask, ret, alt)) => {
            if let Some(c) = sched::live::current() {
                c.set_current_blocked(sigmask);
                restore_altstack(&c, alt);
            }
            ret
        }
        None => sched::live::terminate_current_with_signal(sched::live::Signum::Sigsegv.as_u8()),
    }
}

/// Linux `restore_altstack`: re-apply the `uc_stack` the frame carried, which
/// is how an `SS_AUTODISARM` stack comes back after its handler returns.
/// Linux squashes every error but EFAULT here, so a nonsensical `uc_stack`
/// leaves the current one alone rather than killing the task.
/// # C: O(1)
fn restore_altstack(cur: &sched::Task, alt: hal::AltStack) {
    let req = sas::AltStack { sp: alt.sp, size: alt.size, flags: alt.flags };
    if let Ok(Some(new)) = sas::apply(current_user_sp(), cur.altstack(), req) {
        cur.set_altstack(new);
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
