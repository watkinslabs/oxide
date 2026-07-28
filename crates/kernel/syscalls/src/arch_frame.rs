#![cfg(target_os = "oxide-kernel")]

pub use ::fs::sig_dispatch::UserRegs;

/// The live entry frame of the syscall currently dispatching — Linux's `regs`
/// argument, threaded from `entry_SYSCALL_64` / `el0_svc` all the way to
/// `arch_do_signal_or_restart`. ONE accessor for both arches so no caller has
/// to know which per-CPU slot or stack offset holds it.
///
/// aarch64 prefers the TASK-owned pointer: it survives a blocking syscall's
/// context switches, where the per-CPU slot is only a pre-dispatch fallback
/// another task can overwrite (F206).
/// # C: O(1)
pub fn current_user_regs() -> *mut UserRegs {
    #[cfg(target_arch = "aarch64")]
    {
        use core::sync::atomic::Ordering;
        sched::current()
            .map(|task| task.svc_frame.load(Ordering::Acquire))
            .filter(|frame| *frame != 0)
            .map(|frame| frame as *mut UserRegs)
            .unwrap_or_else(hal_aarch64::current_svc_frame)
    }
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::current_pt_regs() }
}

/// Alias kept for the aarch64 diagnostics that speak of the SVC frame
/// specifically. # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn current_svc_frame() -> *mut hal_aarch64::SvcFrame { current_user_regs() }

/// The trapped user PC of the syscall currently dispatching — Linux
/// `KSTK_EIP(current)`, which is what `populate_seccomp_data` puts in
/// `seccomp_data.instruction_pointer` and what `force_sig_seccomp` puts in
/// `si_call_addr`. `0` when there is no live entry frame.
/// # C: O(1)
pub fn current_user_pc() -> u64 {
    let regs = current_user_regs();
    if regs.is_null() { return 0; }
    // SAFETY: `current_user_regs` returns this task's live syscall entry frame on its own kstack; read-only field access under dispatch context.
    unsafe {
        #[cfg(target_arch = "x86_64")]   { (*regs).rip }
        #[cfg(target_arch = "aarch64")]  { (*regs).elr_el1 }
    }
}

/// The syscall number the live entry frame currently carries, re-read after a
/// ptrace stop so a tracer's rewrite is visible (Linux
/// `syscall_get_nr(current, current_pt_regs())`).
/// # SAFETY: `regs` is the live entry frame owned by this dispatch.
/// # C: O(1)
pub unsafe fn frame_syscall_nr(regs: *mut UserRegs) -> u64 {
    // SAFETY: caller's contract — `regs` is the live entry frame for this dispatch and is exclusively owned by this CPU for the read.
    unsafe {
        // x86_64 keeps the syscall number in `rax` (Linux's `orig_ax` slot);
        // aarch64 keeps it in x8.
        #[cfg(target_arch = "x86_64")]  { (*regs).rax }
        #[cfg(target_arch = "aarch64")] { (*regs).gp[8] }
    }
}
