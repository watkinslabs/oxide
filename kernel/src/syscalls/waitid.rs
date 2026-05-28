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
    let mut sa = *args;
    sa.a0 = pid_for_wait4 as u64;
    sa.a1 = local_wstat_ptr;
    sa.a2 = options;
    sa.a3 = 0;
    let rv = crate::syscalls::wait::sys_wait4(&sa);
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
