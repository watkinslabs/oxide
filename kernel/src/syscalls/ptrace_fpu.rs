// Per-arch FPU snapshot/restore for ptrace stop-and-resume.
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
    // SAFETY: running task on this CPU; preempt-off; fpu_state slot is single-mutator per `13§5`; FpuState{X86_64,AArch64} layout matches ArchFpuBuf's 16-byte alignment.
    unsafe {
        let buf = (*cur.fpu_state.get()).0.as_mut_ptr();
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

/// PTRACE_GETFPREGS handler: copy target's FpuState snapshot to
/// user. Snapshot is populated at every ptrace-stop via
/// `snapshot_current`. Buffer size matches per-arch FXSAVE / NEON.
/// # C: O(n) — 512 / 528 byte copy.
pub fn get_fpregs(pid: u32, data: u64) -> i64 {
    use syscall::errno::Errno;
    let target = match sched::live::registry::lookup(pid) {
        Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
    };
    #[cfg(target_arch = "x86_64")]
    let n: usize = 512;
    #[cfg(target_arch = "aarch64")]
    let n: usize = 528;
    if let Err(rv) = crate::syscalls::validate_user_buf(data, n as u64, 16) { return rv; }
    // SAFETY: target parked under ptrace; fpu_state single-mutator per `13§5`; CPL=0 copies 512/528B into a validated user buffer.
    unsafe {
        let src = (*target.fpu_state.get()).0.as_ptr();
        for i in 0..n {
            core::ptr::write_volatile((data + i as u64) as *mut u8,
                core::ptr::read(src.add(i)));
        }
    }
    0
}

/// PTRACE_SETFPREGS handler: copy user bytes into target's FpuState
/// slot and mark dirty so the target's resume tail restores from
/// the slot before returning to user mode.
/// # C: O(n) — 512 / 528 byte copy.
pub fn set_fpregs(pid: u32, data: u64) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let target = match sched::live::registry::lookup(pid) {
        Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
    };
    #[cfg(target_arch = "x86_64")]
    let n: usize = 512;
    #[cfg(target_arch = "aarch64")]
    let n: usize = 528;
    if let Err(rv) = crate::syscalls::validate_user_buf(data, n as u64, 16) { return rv; }
    // SAFETY: target parked under ptrace; fpu_state single-mutator per `13§5`; CPL=0 reads from a validated user buffer into the per-task FPU slot.
    unsafe {
        let dst = (*target.fpu_state.get()).0.as_mut_ptr();
        for i in 0..n {
            core::ptr::write(dst.add(i),
                core::ptr::read_volatile((data + i as u64) as *const u8));
        }
    }
    target.ptrace_fpu_dirty.store(true, Ordering::Release);
    0
}

/// If the tracer modified our FPU snapshot via PTRACE_SETFPREGS
/// (ptrace_fpu_dirty), restore from the slot so user-mode resumes
/// with the new FP state. Called at the resume tail of
/// `ptrace_syscall_stop_if_armed` after `stop_until_cont` returns.
/// # C: O(1) — one FXRSTOR / per-arch restore.
pub fn restore_if_dirty() {
    let cur = match sched::live::current() { Some(c) => c, None => return };
    if !cur.ptrace_fpu_dirty.swap(false, Ordering::AcqRel) { return; }
    // SAFETY: running task on this CPU; preempt-off; fpu_state slot is single-mutator per `13§5`; restore loads 512/528 B from a validated per-task buffer; matches the snapshot in snapshot_current.
    unsafe {
        let buf = (*cur.fpu_state.get()).0.as_ptr();
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
