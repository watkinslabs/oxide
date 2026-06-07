// 252 ioprio_get — one syscall, one file (docs/53 §0).
//
// ioprio_get(which, who): return the I/O priority of the target. For PGRP/USER
// (multiple tasks) Linux returns the *highest* priority found — lowest class
// number (RT<BE<IDLE), then lowest level. which: PROCESS=1/PGRP=2/USER=3.

use core::sync::atomic::Ordering;
use syscall::errno::Errno;
use syscall::SyscallArgs;

/// Higher I/O priority = lower class (RT=1 < BE=2 < IDLE=3; NONE=0 ranks as BE),
/// then lower level. Returns the more-favorable of `a`/`b`.
fn higher(a: u16, b: u16) -> u16 {
    let rank = |v: u16| -> u16 { let c = v >> 13; if c == 0 { 2 } else { c } };
    let (ra, rb) = (rank(a), rank(b));
    if ra != rb { if ra < rb { a } else { b } }
    else if (a & 0x1fff) <= (b & 0x1fff) { a } else { b }
}

/// `sys_ioprio_get(which, who)` — slot 252.
/// # C: O(N_tasks) for PGRP/USER
pub fn sys_ioprio_get(args: &SyscallArgs) -> i64 {
    let which = args.a0;
    let who   = args.a1 as u32;
    if !(1..=3).contains(&which) { return -(Errno::Einval.as_i32() as i64); }
    let mut best: Option<u16> = None;
    crate::priority::for_each_target(which - 1, who, |t| {
        let v = t.ioprio.load(Ordering::Acquire);
        best = Some(match best { None => v, Some(b) => higher(b, v) });
    });
    match best { Some(v) => v as i64, None => -(Errno::Esrch.as_i32() as i64) }
}
