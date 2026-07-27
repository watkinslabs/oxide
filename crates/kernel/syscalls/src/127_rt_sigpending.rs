// 127 rt_sigpending — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::validate_user_buf_writable;

/// `sys_rt_sigpending(set, sigsetsize)` — slot 127.
///
/// Linux `SYSCALL_DEFINE2(rt_sigpending)` + `do_sigpending`, in order:
///   1. `sigsetsize > sizeof(sigset_t)` → EINVAL. Note `>`, not `!=`: a
///      SMALLER size is legal and copies only that many bytes.
///   2. set = thread-private pending OR process-directed (shared) pending.
///   3. set &= blocked. POSIX reports signals that are pending AND blocked;
///      an unblocked pending signal is delivered before this ever returns.
///   4. `copy_to_user(uset, &set, sigsetsize)` → EFAULT.
/// # C: O(1)
pub fn sys_rt_sigpending(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let set = args.a0;
    let sz  = args.a1;
    if syscall::sigset::check_max(sz).is_err() { return -(Errno::Einval.as_i32() as i64); }
    if sz == 0 { return 0; }  // `copy_to_user(_, _, 0)` never faults
    if let Err(rv) = validate_user_buf_writable(set, sz, 1) { return rv; }
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    let pending = sched::live::sigpend::all_pending(&cur);
    let reported = pending & cur.sigmask.load(Ordering::Acquire);
    let bytes = reported.to_ne_bytes();
    for i in 0..sz as usize {
        // SAFETY: `set..set+sz` validated writable above and `sz <= SIGSET_BYTES`,
        // so every index is inside both the user buffer and `bytes`.
        unsafe { core::ptr::write_unaligned((set as *mut u8).add(i), bytes[i]); }
    }
    0
}

use crate::signal_common::SIGSET_BYTES;
