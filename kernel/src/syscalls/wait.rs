// sys_wait4 — extracted from mod.rs to honor the 1000-line cap.
// Implements POSIX wait4(2) including WNOHANG / WUNTRACED / WCONTINUED.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

const WNOHANG:    u64 = 1;
const WUNTRACED:  u64 = 2;
const WCONTINUED: u64 = 8;

/// `sys_wait4(pid, wstatus, options, rusage)`.
/// # C: O(N_loop × N_children)
pub fn sys_wait4(args: &SyscallArgs) -> i64 {
    let pid     = args.a0 as i32;
    let wstatus = args.a1;
    let options = args.a2;
    let _rusage = args.a3;

    let parent_tid = match sched::live::current() {
        Some(c) => c.tid,
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    let want_stop = (options & WUNTRACED)  != 0;
    let want_cont = (options & WCONTINUED) != 0;
    loop {
        if want_stop || want_cont {
            if let Some((tid, kind, sig)) = sched::live::registry::take_child_stop_event(
                parent_tid, pid, want_stop, want_cont)
            {
                let wstat: i32 = if kind == 1 { ((sig as i32) << 8) | 0x7f } else { 0xffff };
                write_wstatus(wstatus, wstat);
                return tid as i64;
            }
        }
        if let Some((tid, code)) = sched::live::reap_one(parent_tid, pid) {
            let wstat: i32 = if code & 0x100 != 0 { code & 0x7f } else { (code & 0xff) << 8 };
            write_wstatus(wstatus, wstat);
            debug_sched! { klog::write_raw(b"[INFO]  sys_wait4: reaped\n"); }
            return tid as i64;
        }
        if !sched::live::registry::has_children(parent_tid) {
            return -(Errno::Echild.as_i32() as i64);
        }
        if (options & WNOHANG) != 0 { return 0; }
        // SAFETY: process ctx; runqueue installed; preempt-off; park+schedule per `13§8`.
        unsafe { sched::live::park_for_wait4(); }
        // SAFETY: process ctx; runqueue installed; preempt-off.
        unsafe { sched::live::schedule(); }
    }
}

#[inline]
fn write_wstatus(ptr: u64, val: i32) {
    if ptr != 0 && ptr < USER_VA_END {
        // SAFETY: ptr validated < USER_VA_END; user page mapped per `13§5`; CPL=0 write.
        unsafe { core::ptr::write_volatile(ptr as *mut i32, val); }
    }
}
