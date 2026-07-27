// 270 pselect6 — one syscall, one file (docs/53 §0). Moved verbatim from select.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::TimerOps;

use crate::select::s023_select::sys_select_with_deadline;
use crate::userbuf::validate_user_buf;

/// `sys_pselect6(nfds, r, w, e, timeout, sigmask_pair)` — slot 270.
///
/// Two ABI differences vs slot 23 `sys_select`:
///   1. `timeout` is `timespec { sec, nsec }` (nsec resolution) instead
///      of `timeval { sec, usec }`. Both are 16 bytes, same layout.
///      Convert it to a deadline before entering the shared select engine.
///   2. `args.a5` carries a pointer to a 16-byte pair
///      `{ sigmask_ptr: u64, sigmask_size: u64 }` Linux uses to
///      atomically swap the task's sigmask for the duration of the
///      call (`pselect6` is `select` + an atomic sigprocmask).
///      Without honoring it, dropbear's `pselect`-style relay
///      (block SIGCHLD via sigprocmask; pselect with an oldset that
///      unblocks SIGCHLD; restore on return) blocks SIGCHLD across
///      the entire select. The shell child's SIGCHLD posts to
///      sigpending but never delivers → no wait4 → FdTable leaks →
///      pipe POLL_HUP never propagates → no CHANNEL_EOF. F205.
/// # C: O(nfds)
pub fn sys_pselect6(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    debug_ssh! {
        klog::write_raw(b"[INFO]  ssh-trace: pselect6 nfds=");
        klog::write_dec_u64(args.a0);
        klog::write_raw(b" timeout=");
        klog::write_hex_u64(args.a4);
        klog::write_raw(b" sigmask_pair=");
        klog::write_hex_u64(args.a5);
        klog::write_raw(b"\n");
    }
    // 1) Convert timespec to the shared select deadline representation.
    let deadline_ns = if args.a4 == 0 {
        None
    } else {
        if let Err(rv) = validate_user_buf(args.a4, 16, 1) { return rv; }
        // SAFETY: args.a4 validated as a readable 16-byte user timespec.
        let (s, ns) = unsafe {
            (
                core::ptr::read_unaligned( args.a4        as *const i64),
                core::ptr::read_unaligned((args.a4 + 8)   as *const i64),
            )
        };
        // `ktime_set`-clamped decode: a huge-but-valid tv_sec clamps to
        // KTIME_MAX_NS instead of an unbounded relative timeout.
        let total_ns = match ::syscall::time::timespec_to_ns(s, ns) {
            Ok(ns) => ns,
            Err(_) => return -(Errno::Einval.as_i32() as i64),
        };
        #[cfg(target_arch = "x86_64")]
        let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
        #[cfg(target_arch = "aarch64")]
        let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        Some(now.saturating_add(total_ns))
    };
    // 2) Atomically install the caller's sigmask. The pair at a5 is
    //    `{ const sigset_t *ss; size_t ss_len; }`.
    let cur = sched::live::current();
    let saved_mask = if args.a5 != 0 {
        if let Err(rv) = validate_user_buf(args.a5, 16, 1) { return rv; }
        // SAFETY: args.a5 validated as a readable 16-byte user pair.
        let (ss_ptr, ss_len) = unsafe {
            (
                core::ptr::read_unaligned(args.a5 as *const u64),
                core::ptr::read_unaligned((args.a5 + 8) as *const u64),
            )
        };
        debug_ssh! {
            klog::write_raw(b"[INFO]  ssh-trace: pselect6 a5_pair=");
            klog::write_hex_u64(args.a5);
            klog::write_raw(b" inner_ptr=");
            klog::write_hex_u64(ss_ptr);
            klog::write_raw(b"\n");
        }
        if ss_ptr != 0 {
            if ss_len != 8 { return -(Errno::Einval.as_i32() as i64); }
            if let Err(rv) = validate_user_buf(ss_ptr, 8, 1) { return rv; }
            // SAFETY: ss_ptr validated as a readable 8-byte user sigset_t.
            let new_mask = unsafe { core::ptr::read_unaligned(ss_ptr as *const u64) };
            // SIGKILL (9) and SIGSTOP (19) are non-blockable per signal(7).
            let new_mask = new_mask
                & !(sched::live::sigpend::Signum::Sigkill.bit()
                  | sched::live::sigpend::Signum::Sigstop.bit());
            let r = cur.as_ref().map(|c| c.sigmask.swap(new_mask, Ordering::AcqRel));
            debug_ssh! {
                klog::write_raw(b"[INFO]  ssh-trace: pselect6 swap_mask new=");
                klog::write_hex_u64(new_mask);
                klog::write_raw(b" old=");
                klog::write_hex_u64(r.unwrap_or(0));
                klog::write_raw(b"\n");
            }
            r
        } else {
            None
        }
    } else {
        None
    };
    // 3) Forward to the shared select engine with the converted timeout.
    let inner = SyscallArgs {
        a0: args.a0, a1: args.a1, a2: args.a2, a3: args.a3,
        a4: 0, a5: 0,
    };
    let rv = sys_select_with_deadline(&inner, deadline_ns);
    // 4) Restore the saved sigmask if we swapped. Linux pselect6
    //    semantics: if a deliverable signal is pending at return,
    //    LEAVE the new mask installed so the syscall-tail signal
    //    delivery in `oxide_syscall_dispatch` actually delivers it
    //    (the signal handler's rt_sigreturn then restores the mask
    //    saved on the user signal frame, which equals the new mask;
    //    user-space follow-up sigprocmask resets to background).
    //    No deliverable signal pending → restore old mask immediately
    //    so post-pselect user code sees its original mask. Mirrors
    //    Linux's restore_user_sigmask / TIF_RESTORE_SIGMASK path.
    if let Some(old) = saved_mask {
        if let Some(c) = cur.as_ref() {
            let pending = c.sigpending.load(Ordering::Acquire);
            let cur_mask = c.sigmask.load(Ordering::Acquire);
            if pending & !cur_mask == 0 {
                c.sigmask.store(old, Ordering::Release);
            }
        }
    }
    rv
}
