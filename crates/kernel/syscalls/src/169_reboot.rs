// 169 reboot — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

/// reboot(magic1, magic2, cmd, arg) per Linux reboot(2).
/// Validates magic numbers, requires CAP_SYS_BOOT, then dispatches
/// through the `power` crate. RESTART/POWER_OFF/HALT are irreversible
/// and never return; CAD_ON/CAD_OFF return 0; KEXEC returns EINVAL.
/// # C: O(1)
pub fn sys_reboot(args: &SyscallArgs) -> i64 {
    let magic1 = args.a0 as u32;
    let magic2 = args.a1 as u32;
    let c      = args.a2 as u32;
    if !power::check_magic(magic1, magic2) { return errno(Errno::Einval); }
    let cur = match sched::live::current() { Some(c) => c, None => return errno(Errno::Eperm) };
    use core::sync::atomic::Ordering;
    if (cur.creds.cap_effective.load(Ordering::Acquire) >> sched::cap::SYS_BOOT) & 1 == 0 {
        return errno(Errno::Eperm);
    }
    // SAFETY: capability + magic validated above; cmd is irreversible per power(2) contract.
    match unsafe { power::cmd(c) } {
        Ok(())                       => 0,
        Err(power::Error::Inval)     => errno(Errno::Einval),
        Err(power::Error::Perm)      => errno(Errno::Eperm),
        Err(power::Error::Io)        => errno(Errno::Eio),
    }
}
