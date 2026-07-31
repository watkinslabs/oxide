// 098 getrusage — one syscall, one file (docs/53 §0). Layout, `who`
// validation, and the encoder are pure and live in `syscall::rusage`, shared
// with the `wait4`/`waitid` rusage out-param.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_getrusage(who, usage)` — slot 98. RUSAGE_SELF/THREAD report the
/// calling task's tick-sampled CPU time plus its page-fault, block-I/O and
/// context-switch counters; RUSAGE_CHILDREN reports the reaped children's
/// cumulative CPU time. `ru_maxrss` stays 0 — no RSS high-water accounting
/// exists to source it from.
/// # C: O(1)
pub fn sys_getrusage(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    use syscall::rusage::{bytes_to_blocks, getrusage_who_valid, Rusage, RUSAGE_CHILDREN};
    let who = args.a0 as i32;
    let buf = args.a1;
    if !getrusage_who_valid(who) { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let r = if who == RUSAGE_CHILDREN {
        // Only CPU time is accumulated per reaped child today; the remaining
        // c* counters have no accumulator behind them and stay 0.
        Rusage {
            utime_ns: cur.cumulative_child_utime_ns.load(Ordering::Acquire),
            stime_ns: cur.cumulative_child_stime_ns.load(Ordering::Acquire),
            ..Rusage::default()
        }
    } else {
        Rusage {
            utime_ns:  cur.utime_ns.load(Ordering::Acquire),
            stime_ns:  cur.stime_ns.load(Ordering::Acquire),
            maxrss_kb: 0,
            minflt:    cur.min_flt.load(Ordering::Relaxed),
            majflt:    cur.maj_flt.load(Ordering::Relaxed),
            inblock:   bytes_to_blocks(cur.io_read_bytes.load(Ordering::Relaxed)),
            oublock:   bytes_to_blocks(cur.io_write_bytes.load(Ordering::Relaxed)),
            nvcsw:     cur.nvcsw.load(Ordering::Relaxed),
            nivcsw:    cur.nivcsw.load(Ordering::Relaxed),
        }
    };
    // `buf == 0` is a genuine EFAULT here, unlike the wait-family's optional
    // out-param, so validate before handing the pointer to the shared writer.
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(buf, syscall::rusage::RUSAGE_BYTES as u64, 1) { return rv; }
    match crate::wait::write_rusage_bytes(buf, r) { Ok(()) => 0, Err(rv) => rv }
}
