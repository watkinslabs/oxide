// 271 ppoll — one syscall, one file (docs/53 §0).
#![cfg(any(target_os = "oxide-kernel", test))]

use syscall::SyscallArgs;

use crate::poll::s007_poll::{current_task, sys_poll_deadline};
use crate::pselect_ppoll_edge::{poll_select_finish, poll_select_set_timeout, set_user_sigmask};

/// `sys_ppoll(ufds, nfds, tsp, sigmask, sigsetsize)` — slot 271.
///
/// Linux `SYSCALL_DEFINE5(ppoll)`, in this exact order:
///   1. `tsp` is a `struct __kernel_timespec` (ns), not poll's `int ms`:
///      EFAULT then EINVAL, both before any mask is installed. NULL blocks
///      indefinitely; `{0,0}` polls without blocking.
///   2. `set_user_sigmask(sigmask, sigsetsize)` — a NULL `sigmask` leaves the
///      mask alone whatever `sigsetsize` says; otherwise the mask is
///      installed atomically with the wait and `TIF_RESTORE_SIGMASK` armed.
///   3. `do_sys_poll`.
///   4. `poll_select_finish`: restore the saved mask unless the wait ended in
///      `-ERESTARTNOHAND`, then write the remaining time back to `tsp`.
/// # C: O(nfds × N_loop)
pub fn sys_ppoll(args: &SyscallArgs) -> i64 {
    let tsp = args.a2;
    let (req_sec, req_nsec, deadline_ns) = match poll_select_set_timeout(tsp) {
        Ok(v)  => v,
        Err(e) => return e,
    };
    let cur = current_task();
    if let Err(e) = set_user_sigmask(cur, args.a3, args.a4) { return e; }
    let rv = sys_poll_deadline(args.a0, args.a1, deadline_ns);
    poll_select_finish(cur, rv, tsp, req_sec, req_nsec, deadline_ns)
}
