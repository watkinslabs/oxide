// 270 pselect6 — one syscall, one file (docs/53 §0).
#![cfg(any(target_os = "oxide-kernel", test))]

use syscall::SyscallArgs;

use crate::pselect_ppoll::{SIGSET_ARGPACK_BYTES, SIGSET_ARGPACK_LEN_OFF};
use crate::pselect_ppoll_edge::{poll_select_finish, poll_select_set_timeout, set_user_sigmask};
use crate::select::s023_select::sys_select_with_deadline;
use crate::userbuf::validate_user_buf;

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

/// `sys_pselect6(nfds, r, w, e, tsp, sigpack)` — slot 270.
///
/// Linux `SYSCALL_DEFINE6(pselect6)` → `get_sigset_argpack` → `do_pselect`,
/// in this exact order (an earlier step's error wins over a later one):
///   1. `sig` is a POINTER to `struct sigset_argpack { const sigset_t *ss;
///      size_t ss_len; }` — read FIRST, EFAULT on a bad pack. Treating a5 as
///      a bare `sigset_t *` is the classic pselect6 ABI bug.
///   2. `tsp` is a `struct __kernel_timespec` (ns), not select's `timeval`:
///      EFAULT then EINVAL, both before the wait.
///   3. `set_user_sigmask` installs the mask atomically with the wait and
///      arms `TIF_RESTORE_SIGMASK`; a NULL `ss` leaves the mask alone.
///   4. `core_sys_select`.
///   5. `poll_select_finish`: restore the saved mask unless the wait ended in
///      `-ERESTARTNOHAND`, then write the remaining time back to `tsp`.
/// # C: O(nfds)
pub fn sys_pselect6(args: &SyscallArgs) -> i64 {
    debug_ssh! {
        klog::write_raw(b"[INFO]  ssh-trace: pselect6 nfds=");
        klog::write_dec_u64(args.a0);
        klog::write_raw(b" timeout=");
        klog::write_hex_u64(args.a4);
        klog::write_raw(b" sigmask_pair=");
        klog::write_hex_u64(args.a5);
        klog::write_raw(b"\n");
    }
    // 1) The sigset argpack, before anything else — Linux reads it in the
    //    syscall entry, so a faulting pack is EFAULT even when the timespec
    //    is also malformed.
    let (ss_ptr, ss_len) = if args.a5 == 0 { (0, 0) } else {
        if let Err(rv) = validate_user_buf(args.a5, SIGSET_ARGPACK_BYTES, 1) { return rv; }
        // SAFETY: args.a5 validated readable for the whole 16-byte sigset_argpack.
        unsafe {
            (core::ptr::read_unaligned(args.a5 as *const u64),
             core::ptr::read_unaligned((args.a5 + SIGSET_ARGPACK_LEN_OFF) as *const u64))
        }
    };
    debug_ssh! {
        klog::write_raw(b"[INFO]  ssh-trace: pselect6 a5_pair=");
        klog::write_hex_u64(args.a5);
        klog::write_raw(b" inner_ptr=");
        klog::write_hex_u64(ss_ptr);
        klog::write_raw(b"\n");
    }
    // 2) timespec → absolute deadline.
    let (req_sec, req_nsec, deadline_ns) = match poll_select_set_timeout(args.a4) {
        Ok(v)  => v,
        Err(e) => return e,
    };
    // 3) Atomic mask install + TIF_RESTORE_SIGMASK.
    let cur = current_task();
    if let Err(e) = set_user_sigmask(cur, ss_ptr, ss_len) { return e; }
    // 4) The shared select engine, with the pselect6 deadline.
    let inner = SyscallArgs {
        a0: args.a0, a1: args.a1, a2: args.a2, a3: args.a3,
        a4: 0, a5: 0,
    };
    let rv = sys_select_with_deadline(&inner, deadline_ns);
    // 5) Mask restore (unless interrupted) + remaining-time writeback.
    poll_select_finish(cur, rv, args.a4, req_sec, req_nsec, deadline_ns)
}
