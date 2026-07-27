// 297 rt_tgsigqueueinfo — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::signal_common::*;
use crate::userbuf::validate_user_buf;

/// `sys_rt_tgsigqueueinfo(tgid, tid, sig, info)` — slot 297.
///
/// Linux `do_rt_tgsigqueueinfo`, in order: EFAULT on the siginfo copy, EINVAL
/// for `tid <= 0 || tgid <= 0`, then the same si_code forgery guard as
/// `rt_sigqueueinfo` (129) compared against the `tid` argument, then
/// `do_send_specific` — ESRCH unless `tid` names a live thread of `tgid`.
/// Thread-directed, so the record lands on that thread, never the group.
/// # C: O(1) after the registry lookup
pub fn sys_rt_tgsigqueueinfo(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let tgid = args.a0 as i32;
    let tid  = args.a1 as i32;
    let sig  = args.a2 as i32;
    let info_ptr = args.a3;
    if let Err(rv) = validate_user_buf(info_ptr, KERNEL_SIGINFO_BYTES, 1) { return rv; }
    let info = read_user_siginfo(info_ptr, sig as u32);
    if tid <= 0 || tgid <= 0 { return -(Errno::Einval.as_i32() as i64); }
    if crate::s129_rt_sigqueueinfo::forgery_rejected(info.code, tid) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    if sig < 0 { return -(Errno::Einval.as_i32() as i64); }
    // `do_send_specific`: the thread must actually belong to `tgid`.
    match sched::live::registry::resolve_user_pid(tid as u32) {
        Some(t) if t.vtgid.load(Ordering::Acquire) == tgid as u32 => {}
        _ => return -(Errno::Esrch.as_i32() as i64),
    }
    sigqueue_to(tid as u32, sig as u32, info)
}
