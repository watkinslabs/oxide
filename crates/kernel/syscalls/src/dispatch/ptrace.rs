#![cfg(target_os = "oxide-kernel")]

/// PTRACE_SYSCALL self-stop. # C: O(1)
pub(super) fn ptrace_syscall_stop_if_armed() {
    use core::sync::atomic::Ordering;
    use sched::Signum;
    let cur = match sched::live::current() { Some(c) => c, None => return };
    if cur.traced_by.load(Ordering::Acquire) == 0 { return; }
    if !cur.ptrace_syscall_armed.swap(false, Ordering::AcqRel) { return; }
    let opts = cur.ptrace_options.load(Ordering::Acquire);
    let code = if (opts & 0x1) != 0 { 0x80 } else { 0 };
    let tracer = cur.traced_by.load(Ordering::Acquire);
    *cur.ptrace_siginfo.lock() = Some(sched::SigInfo { signo: Signum::Sigtrap as u32, code, pid: tracer, uid: 0, value: 0 });
    crate::ptrace_fpu::snapshot_current();
    cur.sigpending.fetch_or(Signum::Sigtrap.bit(), Ordering::Release);
    unsafe { sched::live::stop::stop_until_cont_sig(Signum::Sigtrap as u8); }
    crate::ptrace_fpu::restore_if_dirty();
}
