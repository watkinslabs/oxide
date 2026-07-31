// 098 getrusage — one syscall, one file (docs/53 §0). Layout, `who`
// validation, and the encoder are pure and live in `syscall::rusage`, shared
// with the `wait4`/`waitid` rusage out-param.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_getrusage(who, usage)` — slot 98. RUSAGE_SELF/THREAD report the
/// calling task's tick-sampled CPU time plus its page-fault, block-I/O and
/// context-switch counters; RUSAGE_CHILDREN reports the same set accumulated
/// from every child the PROCESS has reaped. `ru_maxrss` stays 0 — no RSS
/// high-water accounting exists to source it from.
/// # C: O(1)
pub fn sys_getrusage(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    use syscall::rusage::{getrusage_who_valid, RUSAGE_CHILDREN};
    let who = args.a0 as i32;
    let buf = args.a1;
    if !getrusage_who_valid(who) { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let r = if who == RUSAGE_CHILDREN { cur.thread_group.child_acct().snapshot() }
            else                        { sched::registry::task_rusage_self(&cur) };
    // `buf == 0` is a genuine EFAULT here, unlike the wait-family's optional
    // out-param, so validate before handing the pointer to the shared writer.
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(buf, syscall::rusage::RUSAGE_BYTES as u64, 1) { return rv; }
    match crate::wait::write_rusage_bytes(buf, r) { Ok(()) => 0, Err(rv) => rv }
}
