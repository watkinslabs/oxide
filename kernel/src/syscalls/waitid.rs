// sys_waitid — extracted from syscalls/mod.rs per docs/08§7 cap.
// Linux idtype P_ALL/P_PID/P_PGID maps to wait4; populates a
// canonical siginfo_t in user memory (si_signo / si_code /
// si_pid / si_status) from the wait4-encoded wstat. P_PIDFD
// not honored in v1 (treat id as pid).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use hal::USER_VA_END;

/// # C: same as wait4 — bounded by zombie poll
pub fn sys_waitid(args: &SyscallArgs) -> i64 {
    const P_ALL: u64 = 0;
    const P_PID: u64 = 1;
    const P_PGID: u64 = 2;
    const WNOHANG: u64 = 1;
    const WNOWAIT: u64 = 0x0100_0000;
    let idtype  = args.a0;
    let id      = args.a1 as i32;
    let infop   = args.a2;
    let options = args.a3;
    let pid_for_wait4: i32 = match idtype {
        P_ALL  => -1,
        P_PID  => id,
        P_PGID => -id,
        _      => id, // P_PIDFD: treat as pid in v1
    };
    let mut local_wstat: i32 = 0;
    let local_wstat_ptr = &mut local_wstat as *mut i32 as u64;
    // WNOWAIT (waitid-only): peek the zombie's status but leave it
    // waitable. systemd's SIGCHLD handler peeks with WEXITED|WNOHANG|
    // WNOWAIT to map a pid→unit, then reaps separately; if the peek
    // reaped, that second wait returns ECHILD ("Failed to dequeue
    // child") and systemd mis-supervises the service (the console-getty
    // restart loop). Delegating to wait4 here would reap — so handle
    // WNOWAIT without touching the zombie queue.
    let rv = if options & WNOWAIT != 0 {
        let parent_tid = match sched::live::current() { Some(c) => c.tid, None => 0 };
        match sched::live::peek_one(parent_tid, pid_for_wait4) {
            Some((tid, code)) => {
                local_wstat = if code & 0x100 != 0 { code & 0x7f } else { (code & 0xff) << 8 };
                tid as i64
            }
            None => {
                if !sched::live::registry::has_children(parent_tid) {
                    -(syscall::errno::Errno::Echild.as_i32() as i64)
                } else if options & WNOHANG != 0 {
                    0
                } else {
                    // Blocking WNOWAIT without WNOHANG: park until a child
                    // exits, then re-peek. systemd always pairs WNOHANG,
                    // so this path is rare but POSIX-correct.
                    // SAFETY: process ctx; runqueue installed; preempt-off; park+reschedule per `13§8`.
                    unsafe { sched::live::park_for_wait4(); sched::live::schedule(); }
                    match sched::live::peek_one(parent_tid, pid_for_wait4) {
                        Some((tid, code)) => {
                            local_wstat = if code & 0x100 != 0 { code & 0x7f } else { (code & 0xff) << 8 };
                            tid as i64
                        }
                        None => 0,
                    }
                }
            }
        }
    } else {
        let mut sa = *args;
        sa.a0 = pid_for_wait4 as u64;
        sa.a1 = local_wstat_ptr;
        sa.a2 = options;
        sa.a3 = 0;
        crate::syscalls::wait::sys_wait4(&sa)
    };
    if infop != 0 && infop < USER_VA_END {
        let (si_code, si_status): (i32, i32) = if rv > 0 {
            if (local_wstat & 0x7f) == 0 {
                (1, (local_wstat >> 8) & 0xff)            // CLD_EXITED
            } else if (local_wstat & 0xff) == 0x7f {
                (5, (local_wstat >> 8) & 0xff)            // CLD_STOPPED
            } else {
                (2, local_wstat & 0x7f)                   // CLD_KILLED
            }
        } else { (0, 0) };
        // SAFETY: infop validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe {
            for i in 0..128usize {
                core::ptr::write_volatile((infop + i as u64) as *mut u8, 0);
            }
            if rv > 0 {
                core::ptr::write_volatile(infop        as *mut i32, 17 /* SIGCHLD */);
                core::ptr::write_volatile((infop + 8)  as *mut i32, si_code);
                core::ptr::write_volatile((infop + 16) as *mut i32, rv as i32);
                core::ptr::write_volatile((infop + 24) as *mut i32, si_status);
            }
        }
    }
    if rv < 0 { rv } else { 0 }
}
