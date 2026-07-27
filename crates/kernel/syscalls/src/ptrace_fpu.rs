// Per-arch FPU snapshot/restore for ptrace stop-and-resume. The register
// and user-area transfers themselves live in `101_ptrace/{mem,regset}.rs`;
// this file is only the two hooks the tracee itself runs around a stop.
// Snapshots into Task.fpu_state at every ptrace-stop so the tracer's
// PTRACE_GETFPREGS sees live state. After resume, if the tracer
// touched the snapshot via SETFPREGS (ptrace_fpu_dirty=true), runs
// fpu_restore from the slot so the user resumes with the modified
// FP state.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

/// Snapshot the current task's live FPU state into its
/// `fpu_state` slot. Called from `ptrace_syscall_stop_if_armed`
/// before parking so PTRACE_GETFPREGS sees the user's FP regs.
/// # C: O(1) — one FXSAVE / per-arch save.
pub fn snapshot_current() {
    let cur = match sched::live::current() { Some(c) => c, None => return };
    if cur.traced_by.load(Ordering::Acquire) == 0 { return; }
    cur.debug_check_fpu_state("ptrace-snapshot-current");
    // SAFETY: running task on this CPU; preempt-off; fpu_state slot is single-mutator per `13§5`; FpuState{X86_64,AArch64} layout matches ArchFpuBuf's 16-byte alignment.
    unsafe {
        let buf = (*cur.fpu_state.get()).as_mut_ptr();
        #[cfg(target_arch = "x86_64")]
        {
            hal_x86_64::fpu_save(buf as *mut hal_x86_64::FpuStateX86_64);
        }
        #[cfg(target_arch = "aarch64")]
        {
            hal_aarch64::fpu_save(buf as *mut hal_aarch64::FpuStateAArch64);
        }
    }
}

/// If the tracer modified our FPU snapshot via PTRACE_SETFPREGS
/// (ptrace_fpu_dirty), restore from the slot so user-mode resumes
/// with the new FP state. Called at the resume tail of
/// `ptrace_syscall_stop_if_armed` after `stop_until_cont` returns.
/// # C: O(1) — one FXRSTOR / per-arch restore.
pub fn restore_if_dirty() {
    let cur = match sched::live::current() { Some(c) => c, None => return };
    if !cur.ptrace_fpu_dirty.swap(false, Ordering::AcqRel) { return; }
    cur.debug_check_fpu_state("ptrace-restore-current");
    // SAFETY: running task on this CPU; preempt-off; fpu_state slot is single-mutator per `13§5`; restore loads 512/528 B from a validated per-task buffer; matches the snapshot in snapshot_current.
    unsafe {
        let buf = (*cur.fpu_state.get()).as_ptr();
        #[cfg(target_arch = "x86_64")]
        {
            hal_x86_64::fpu_restore(buf as *const hal_x86_64::FpuStateX86_64);
        }
        #[cfg(target_arch = "aarch64")]
        {
            hal_aarch64::fpu_restore(buf as *const hal_aarch64::FpuStateAArch64);
        }
    }
}
