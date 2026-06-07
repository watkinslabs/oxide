// 315 sched_getattr — one syscall, one file (docs/53 §0).
//
// sched_getattr(pid, attr, size, flags): fill the caller's struct sched_attr
// with the target task's scheduling policy, nice, and RT priority. Read-only —
// reflects real Task state (class/nice). sched_setattr (314), which mutates the
// class + migrates runqueues, is a separate deferred syscall. flags must be 0;
// the user `size` must be ≥ the 48-byte sched_attr.

use core::sync::atomic::Ordering;
use sched::{SchedClass, SchedPolicy};
use syscall::{errno::Errno, SyscallArgs};

const SCHED_ATTR_SIZE: u32 = 48;

/// `sys_sched_getattr(pid, attr, size, flags)` — slot 315.
/// # C: O(1) self; O(N) for a foreign pid
pub fn sys_sched_getattr(args: &SyscallArgs) -> i64 {
    let pid   = args.a0 as u32;
    let uattr = args.a1;
    let size  = args.a2 as u32;
    let flags = args.a3;
    if flags != 0 || size < SCHED_ATTR_SIZE { return -(Errno::Einval.as_i32() as i64); }
    if uattr == 0 || uattr.saturating_add(SCHED_ATTR_SIZE as u64) > hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else {
        sched::live::registry::lookup(pid)
    };
    let t = match task { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };
    // policy: SCHED_OTHER=0, FIFO=1, RR=2, IDLE=5; RT priority from the class.
    let (policy, prio): (u32, u32) = match t.sched_class() {
        SchedClass::Rt { prio, policy: SchedPolicy::Fifo } => (1, prio as u32),
        SchedClass::Rt { prio, policy: SchedPolicy::Rr }   => (2, prio as u32),
        SchedClass::Idle                                   => (5, 0),
        SchedClass::Normal { .. }                          => (0, 0),
        SchedClass::Rt { prio, .. }                        => (0, prio as u32),
    };
    let nice = t.nice.load(Ordering::Acquire) as i32;
    // struct sched_attr (uapi): u32 size, u32 policy, u64 flags, s32 nice,
    // u32 priority, u64 runtime, u64 deadline, u64 period.
    let mut buf = [0u8; SCHED_ATTR_SIZE as usize];
    buf[0..4].copy_from_slice(&SCHED_ATTR_SIZE.to_le_bytes());
    buf[4..8].copy_from_slice(&policy.to_le_bytes());
    // [8..16) sched_flags = 0
    buf[16..20].copy_from_slice(&nice.to_le_bytes());
    buf[20..24].copy_from_slice(&prio.to_le_bytes());
    // [24..48) runtime/deadline/period = 0 (no SCHED_DEADLINE)
    // SAFETY: uattr range checked < USER_VA_END above; 48-byte copy into the
    // running task's user AS, which is active during the syscall.
    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), uattr as *mut u8, SCHED_ATTR_SIZE as usize); }
    0
}
