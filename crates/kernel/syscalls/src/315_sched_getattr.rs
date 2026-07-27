// 315 sched_getattr — one syscall, one file (docs/53 §0).
//
// sched_getattr(pid, attr, size, flags): fill the caller's struct sched_attr
// with the target task's scheduling policy, nice, and RT priority. Read-only —
// reflects real Task state (class/nice). sched_setattr (314), which mutates the
// class + migrates runqueues, is a separate deferred syscall. flags must be 0;
// the user `size` must be ≥ the 48-byte sched_attr.

use core::sync::atomic::Ordering;
use syscall::{errno::Errno, SyscallArgs};
use crate::sched_policy;
use crate::userbuf::validate_user_buf_writable;

const SCHED_ATTR_SIZE: u32 = 48;
/// Linux `SCHED_FLAG_RESET_ON_FORK`, reported back in `sched_attr.sched_flags`.
const SCHED_FLAG_RESET_ON_FORK: u64 = 0x01;

/// `sys_sched_getattr(pid, attr, size, flags)` — slot 315.
/// # C: O(1) self; O(N) for a foreign pid
pub fn sys_sched_getattr(args: &SyscallArgs) -> i64 {
    let pid   = match sched_policy::pid_arg(args.a0) { Ok(v) => v, Err(rv) => return rv };
    let uattr = args.a1;
    let size  = args.a2 as u32;
    let flags = args.a3;
    if flags != 0 || size < SCHED_ATTR_SIZE { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = validate_user_buf_writable(uattr, SCHED_ATTR_SIZE as u64, 1) { return rv; }
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else {
        sched::live::registry::resolve_user_pid(pid)
    };
    let t = match task { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };
    // Linux `sched_getattr` reports `p->policy` + `p->rt_priority` — the stored
    // policy, not the implementation class (NORMAL/BATCH/IDLE share CFS).
    let policy = sched_policy::task_policy(&t);
    let prio = sched_policy::task_rt_priority(&t);
    let flags: u64 = if t.sched_reset_on_fork.load(Ordering::Acquire) { SCHED_FLAG_RESET_ON_FORK } else { 0 };
    let nice = t.nice.load(Ordering::Acquire) as i32;
    // struct sched_attr (uapi): u32 size, u32 policy, u64 flags, s32 nice,
    // u32 priority, u64 runtime, u64 deadline, u64 period.
    let mut buf = [0u8; SCHED_ATTR_SIZE as usize];
    buf[0..4].copy_from_slice(&SCHED_ATTR_SIZE.to_le_bytes());
    buf[4..8].copy_from_slice(&policy.to_le_bytes());
    buf[8..16].copy_from_slice(&flags.to_le_bytes());
    buf[16..20].copy_from_slice(&nice.to_le_bytes());
    buf[20..24].copy_from_slice(&prio.to_le_bytes());
    // [24..48) runtime/deadline/period = 0 (no SCHED_DEADLINE)
    // SAFETY: uattr validated writable for the 48-byte sched_attr result.
    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), uattr as *mut u8, SCHED_ATTR_SIZE as usize); }
    0
}
