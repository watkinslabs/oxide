#![cfg(target_os = "oxide-kernel")]

/// Linux `PTRACE_O_TRACESYSGOOD` marker bit OR-ed into the reported stop
/// signal so a tracer can distinguish a syscall stop from a real SIGTRAP.
const SYSCALL_TRAP_BIT: i32 = 0x80;

/// PTRACE_SYSCALL self-stop. `rax` is the value a tracer's GETREGS must see
/// in the ABI return register at this stop: Linux reports `-ENOSYS` at the
/// syscall-entry stop and the real result at the syscall-exit stop. The saved
/// entry frame keeps the syscall number in that slot, so the value is
/// recorded on the task instead of being reconstructed from the frame.
/// # C: O(1)
pub(super) fn ptrace_syscall_stop_if_armed(rax: u64) {
    use core::sync::atomic::Ordering;
    use sched::Signum;
    let cur = match sched::live::current() { Some(c) => c, None => return };
    if cur.traced_by.load(Ordering::Acquire) == 0 { return; }
    if !cur.ptrace_syscall_armed.swap(false, Ordering::AcqRel) { return; }
    cur.ptrace_stop_rax.store(rax, Ordering::Release);
    // Linux `ptrace_report_syscall`: the stop signal reported through
    // wait(2) is `SIGTRAP | 0x80` when PTRACE_O_TRACESYSGOOD is set, which is
    // how a tracer tells a syscall stop from a real SIGTRAP. `ptrace_notify`
    // then stores that same value in `si_code`. Reporting a bare SIGTRAP
    // (what this did) makes strace misclassify every syscall stop.
    let opts = cur.ptrace_options.load(Ordering::Acquire);
    let sysgood = (opts & crate::s101_ptrace_uapi::O_TRACESYSGOOD) != 0;
    let stop_code = Signum::Sigtrap as i32 | if sysgood { SYSCALL_TRAP_BIT } else { 0 };
    let tracer = cur.traced_by.load(Ordering::Acquire);
    *cur.ptrace_siginfo.lock() = Some(sched::SigInfo {
        signo: Signum::Sigtrap as u32, code: stop_code, pid: tracer, uid: 0, value: 0,
    });
    crate::ptrace_fpu::snapshot_current();
    cur.sigpending.fetch_or(Signum::Sigtrap.bit(), Ordering::Release);
    unsafe { sched::live::stop::stop_until_cont_sig(stop_code as u8); }
    crate::ptrace_fpu::restore_if_dirty();
}
