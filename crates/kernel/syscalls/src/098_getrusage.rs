// 098 getrusage — one syscall, one file (docs/53 §0). Layout, `who`
// validation, and the encoder are pure and live in `syscall::rusage`, shared
// with the `wait4`/`waitid` rusage out-param.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_getrusage(who, usage)` — slot 98.
///
/// - `RUSAGE_SELF`: the whole thread group — every live thread plus the
///   residue of every thread that already exited.
/// - `RUSAGE_THREAD`: the calling thread alone (`ru_maxrss` still comes from
///   the shared mm, which is not a per-thread property).
/// - `RUSAGE_CHILDREN`: what the PROCESS accumulated from reaped children,
///   including each reaped child's own children.
///
/// `who` is rejected before the buffer is looked at, so a bad `who` with a bad
/// pointer reports EINVAL, not EFAULT.
/// # C: O(1)
pub fn sys_getrusage(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    use syscall::rusage::{getrusage_source, RusageSource};
    let who = args.a0 as i32;
    let buf = args.a1;
    let Some(source) = getrusage_source(who) else { return -(Errno::Einval.as_i32() as i64) };
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let r = match source {
        RusageSource::ReapedChildren => cur.thread_group.child_acct().snapshot(),
        RusageSource::Thread         => sched::registry::task_rusage_thread(&cur),
        RusageSource::ThreadGroup    => sched::registry::task_rusage_self(&cur),
    };
    // `buf == 0` is a genuine EFAULT here, unlike the wait-family's optional
    // out-param, so validate before handing the pointer to the shared writer.
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(buf, syscall::rusage::RUSAGE_BYTES as u64, 1) { return rv; }
    match crate::wait::write_rusage_bytes(buf, r) { Ok(()) => 0, Err(rv) => rv }
}
