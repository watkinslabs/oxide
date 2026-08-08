// 169 reboot — one syscall, one file (docs/53 §0).
//
// ABI shim only: the magic pair, the command classification, the pid-namespace
// mapping and the RESTART2 string truncation live in `power::decide`
// (ungated, host-tested); the irreversible transition lives in
// `power::machine`.
//
// The check ORDER is the part that is easy to get wrong and is load-bearing:
// `SYSCALL_DEFINE4(reboot)` tests CAP_SYS_BOOT
// FIRST and the magic pair SECOND. An unprivileged caller passing garbage
// magic must see EPERM — reversing the two leaks "these magic numbers were
// wrong" to a process that was never allowed to reboot anything, and makes
// `reboot(0,0,0,0)` from a normal user report EINVAL where Linux says EPERM.

#![cfg(target_os = "oxide-kernel")]


use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

/// `reboot(magic1, magic2, cmd, arg)` per Linux `reboot(2)`.
///
/// Order: CAP_SYS_BOOT → magic pair → `reboot_pid_ns` → command. RESTART /
/// POWER_OFF / HALT / RESTART2 are irreversible and never return; CAD_ON /
/// CAD_OFF latch `C_A_D` and return 0; KEXEC and SW_SUSPEND are EINVAL, the
/// answer a kernel built without CONFIG_KEXEC_CORE / CONFIG_HIBERNATION gives.
/// # C: O(N_devices) on a terminal command, O(1) otherwise
pub fn sys_reboot(args: &SyscallArgs) -> i64 {
    let magic1 = args.a0 as u32;
    let magic2 = args.a1 as u32;
    let cmd    = args.a2 as u32;
    let arg    = args.a3;
    let cur = match sched::live::current() { Some(c) => c, None => return errno(Errno::Eperm) };
    // `ns_capable(pid_ns->user_ns, CAP_SYS_BOOT)` then the magic pair, in that
    // order — see `power::decide::reboot_precheck`.
    match power::reboot_precheck(cur.has_cap(sched::cap::SYS_BOOT), magic1, magic2) {
        Ok(()) => {}
        Err(power::Error::Perm) => return errno(Errno::Eperm),
        Err(_) => return errno(Errno::Einval),
    }
    // `reboot_pid_ns(pid_ns, cmd)`: a caller outside the initial pid namespace
    // never touches the machine — its namespace dies instead.
    if !sched::live::in_initial_pid_namespace(&cur) {
        return reboot_child_pid_ns(&cur, cmd);
    }
    match power::classify_cmd(cmd) {
        Ok(power::RebootAction::SetCad(on)) => { power::set_cad(on); 0 }
        Ok(power::RebootAction::Terminal(t)) => {
            // SAFETY: CAP_SYS_BOOT + magic pair + initial pid namespace all validated above; the transition is irreversible per the reboot(2) contract.
            unsafe { power::terminal(t) }
        }
        Ok(power::RebootAction::Restart2) => restart2(arg),
        Err(power::Error::Inval) => errno(Errno::Einval),
        Err(power::Error::Perm)  => errno(Errno::Eperm),
        Err(power::Error::Io)    => errno(Errno::Eio),
    }
}

/// `LINUX_REBOOT_CMD_RESTART2`: `strncpy_from_user(&buffer[0], arg, 255)` with
/// `-EFAULT` on a bad pointer. The copy happens
/// BEFORE `kernel_restart`, so a caller that passes a garbage pointer gets
/// EFAULT and the machine keeps running — ignoring `arg` and rebooting anyway
/// destroys the caller's chance to learn it made a mistake.
/// # C: O(RESTART2_CMD_BYTES) + O(N_devices)
fn restart2(arg: u64) -> i64 {
    let mut raw = [0u8; power::RESTART2_CMD_BYTES];
    // `strncpy_from_user` stops at the first NUL; a short string next to an
    // unmapped page must not fault, so copy byte by byte.
    for (i, slot) in raw.iter_mut().take(power::RESTART2_CMD_BYTES - 1).enumerate() {
        let mut byte = [0u8; 1];
        if uaccess::copy_from_user(&mut byte, arg.wrapping_add(i as u64)).is_err() {
            return errno(Errno::Efault);
        }
        *slot = byte[0];
        if byte[0] == 0 { break; }
    }
    let len = power::restart2_cmd_len(&raw);
    // SAFETY: CAP_SYS_BOOT + magic pair + initial pid namespace validated by the caller, and the command string is now fully copied in; irreversible by contract.
    unsafe { power::restart_with_command(&raw[..len]) }
}

/// `reboot_pid_ns`: record the reboot
/// signal on the namespace, SIGKILL its `child_reaper`, and `do_exit(0)`.
/// The caller does not return; the namespace's init reports the recorded
/// signal to whoever is watching from outside.
/// # C: O(N_tasks)
fn reboot_child_pid_ns(cur: &sched::Task, cmd: u32) -> i64 {
    let signal = match power::pid_ns_reboot(cmd) {
        Ok(s) => s,
        // Note this rejects CAD_ON/CAD_OFF, which succeed in the initial
        // namespace: `reboot_pid_ns`'s switch has no arms for them.
        Err(_) => return errno(Errno::Einval),
    };
    sched::live::set_pid_namespace_reboot(cur, signal.signo());
    if let Some(reaper) = sched::live::namespace_child_reaper(cur) {
        sched::live::send_sig_priv_group(&reaper, sched::Signum::Sigkill as u32);
    }
    crate::s060_exit::do_exit(0)
}
