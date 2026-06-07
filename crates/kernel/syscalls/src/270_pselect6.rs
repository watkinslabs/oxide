// 270 pselect6 — one syscall, one file (docs/53 §0). Moved verbatim from select.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use hal::USER_VA_END;

use crate::select::s023_select::sys_select;

/// `sys_pselect6(nfds, r, w, e, timeout, sigmask_pair)` — slot 270.
///
/// Two ABI differences vs slot 23 `sys_select`:
///   1. `timeout` is `timespec { sec, nsec }` (nsec resolution) instead
///      of `timeval { sec, usec }`. Both are 16 bytes, same layout.
///      Convert nsec → usec when staging the inner timeval on the
///      kernel stack so sys_select's existing decoder still works.
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
    // 1) Convert timespec → timeval on the kernel stack.
    let inner_timeout: u64;
    let mut tv_buf: [u64; 2] = [0; 2];
    if args.a4 == 0 || args.a4 >= USER_VA_END {
        inner_timeout = 0;
    } else {
        // SAFETY: args.a4 validated < USER_VA_END; user pages mapped via active TTBR0/CR3; CPL=0 reads.
        let (s, ns) = unsafe {
            (
                core::ptr::read_volatile( args.a4        as *const i64),
                core::ptr::read_volatile((args.a4 + 8)   as *const i64),
            )
        };
        // sys_select expects timeval {sec, usec} → convert.
        tv_buf[0] = s as u64;
        tv_buf[1] = (ns / 1000) as u64;
        inner_timeout = tv_buf.as_ptr() as u64;
    }
    // 2) Atomically install the caller's sigmask. The pair at a5 is
    //    `{ const sigset_t *ss; size_t ss_len; }`. Linux ignores
    //    ss_len for compatibility once it's read; we do the same.
    let cur = sched::live::current();
    let saved_mask = if args.a5 != 0 && args.a5 < USER_VA_END {
        // SAFETY: a5 validated < USER_VA_END; 16-byte pair (ptr+len); 8-aligned per ABI.
        let ss_ptr = unsafe { core::ptr::read_volatile(args.a5 as *const u64) };
        debug_ssh! {
            klog::write_raw(b"[INFO]  ssh-trace: pselect6 a5_pair=");
            klog::write_hex_u64(args.a5);
            klog::write_raw(b" inner_ptr=");
            klog::write_hex_u64(ss_ptr);
            klog::write_raw(b"\n");
        }
        if ss_ptr != 0 && ss_ptr < USER_VA_END {
            // SAFETY: ss_ptr validated < USER_VA_END; 8-byte sigset_t per Linux ABI.
            let new_mask = unsafe { core::ptr::read_volatile(ss_ptr as *const u64) };
            // SIGKILL (9) and SIGSTOP (19) are non-blockable per signal(7).
            let new_mask = new_mask & !(1u64 << 8) & !(1u64 << 18);
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
    // 3) Forward to sys_select with the converted timeout.
    let inner = SyscallArgs {
        a0: args.a0, a1: args.a1, a2: args.a2, a3: args.a3,
        a4: inner_timeout, a5: 0,
    };
    let rv = sys_select(&inner);
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
