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

/// PTRACE_PEEKUSER handler: u64 read from target's saved syscall
/// frame at byte offset `addr`. Out-of-reg-range returns 0.
/// # C: O(1)
pub fn peek_user(pid: u32, addr: u64, data: u64) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let addr = addr as usize;
    let target = match sched::live::registry::resolve_user_pid(pid) {
        Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
    };
    target.debug_check_fpu_state("ptrace-get-fpregs");
    let top = target.kernel_stack.load(Ordering::Acquire);
    if top.is_null() { return -(Errno::Esrch.as_i32() as i64); }
    if addr & 7 != 0 { return -(Errno::Eio.as_i32() as i64); }
    #[cfg(target_arch = "x86_64")]
    let (frame_off, n_regs) = (0x80usize, 15usize);
    #[cfg(target_arch = "aarch64")]
    let (frame_off, n_regs) = (0xD0usize, 18usize);
    let reg_idx = addr / 8;
    let word: u64 = if reg_idx < n_regs {
        // SAFETY: target parked; saved frame at kstack_top - frame_off stable while target is parked; aligned u64 read.
        unsafe {
            let frame = (top as u64 - frame_off as u64) as *const u64;
            core::ptr::read_volatile(frame.add(reg_idx))
        }
    } else { 0 };
    if data != 0 && data < ::hal::USER_VA_END {
        // SAFETY: data validated < USER_VA_END; aligned u64 store of peeked word into caller's AS.
        unsafe { core::ptr::write_volatile(data as *mut u64, word); }
    }
    word as i64
}

/// PTRACE_POKEUSER handler: u64 write into target's saved syscall
/// frame at byte offset `addr`. Out-of-reg-range silently drops.
/// # C: O(1)
pub fn poke_user(pid: u32, addr: u64, data: u64) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let addr = addr as usize;
    let target = match sched::live::registry::resolve_user_pid(pid) {
        Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
    };
    target.debug_check_fpu_state("ptrace-set-fpregs");
    let top = target.kernel_stack.load(Ordering::Acquire);
    if top.is_null() { return -(Errno::Esrch.as_i32() as i64); }
    if addr & 7 != 0 { return -(Errno::Eio.as_i32() as i64); }
    #[cfg(target_arch = "x86_64")]
    let (frame_off, n_regs) = (0x80usize, 15usize);
    #[cfg(target_arch = "aarch64")]
    let (frame_off, n_regs) = (0xD0usize, 18usize);
    let reg_idx = addr / 8;
    if reg_idx < n_regs {
        // SAFETY: target parked; saved frame at kstack_top - frame_off stable while target is parked; aligned u64 store.
        unsafe {
            let frame = (top as u64 - frame_off as u64) as *mut u64;
            core::ptr::write_volatile(frame.add(reg_idx), data);
        }
    }
    0
}

/// PTRACE_GETFPREGS handler: copy target's FpuState snapshot to
/// user. Snapshot is populated at every ptrace-stop via
/// `snapshot_current`. Buffer size matches per-arch FXSAVE / NEON.
/// # C: O(n) — 512 / 528 byte copy.
pub fn get_fpregs(pid: u32, data: u64) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    use sched::TaskState;
    let target = match sched::live::registry::resolve_user_pid(pid) {
        Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // Same authorization gap as `set_fpregs` (state.md) -- without this, a
    // caller could read an untraced/still-running target's fpu_state while
    // it's concurrently being torn by that target's own context-switch
    // fpu_save, and could read ANY task's FPU registers regardless of
    // ptrace relationship.
    let cur_tid = match sched::live::current() { Some(c) => c.tid, None => return -(Errno::Esrch.as_i32() as i64) };
    if target.traced_by.load(Ordering::Acquire) != cur_tid { return -(Errno::Esrch.as_i32() as i64); }
    if target.state() != TaskState::Stopped { return -(Errno::Esrch.as_i32() as i64); }
    #[cfg(target_arch = "x86_64")]
    let n: usize = 512;
    #[cfg(target_arch = "aarch64")]
    let n: usize = 528;
    if let Err(rv) = crate::userbuf::validate_user_buf(data, n as u64, 16) { return rv; }
    // SAFETY: target verified traced-by-caller and Stopped above, so its
    // fpu_state cannot be concurrently written by context-switch fpu_save;
    // CPL=0 copies 512/528B into a validated user buffer.
    unsafe {
        let src = (*target.fpu_state.get()).as_ptr();
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
    use sched::TaskState;
    let target = match sched::live::registry::resolve_user_pid(pid) {
        Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // Corruption-hunt fix (state.md): this call's SAFETY comment claimed
    // "target parked under ptrace" but nothing enforced it — any task could
    // resolve any pid and race this write against the target's own
    // context-switch fpu_save/fpu_restore on the SAME `fpu_state` cell (no
    // lock, single-mutator-by-convention only), tearing the XSAVE image and
    // producing a live #GP at a later xrstor64. Linux requires the caller be
    // the tracer (PTRACE_ATTACH/TRACEME set `traced_by`) AND the target be
    // ptrace-stopped before any GETREGS/SETREGS-class request succeeds.
    let cur_tid = match sched::live::current() { Some(c) => c.tid, None => return -(Errno::Esrch.as_i32() as i64) };
    if target.traced_by.load(Ordering::Acquire) != cur_tid { return -(Errno::Esrch.as_i32() as i64); }
    if target.state() != TaskState::Stopped { return -(Errno::Esrch.as_i32() as i64); }
    #[cfg(target_arch = "x86_64")]
    let n: usize = 512;
    #[cfg(target_arch = "aarch64")]
    let n: usize = 528;
    if let Err(rv) = crate::userbuf::validate_user_buf(data, n as u64, 16) { return rv; }
    // SAFETY: target verified traced-by-caller and Stopped above, so it
    // cannot be concurrently scheduled (the picker never re-enqueues a
    // Stopped task); fpu_state single-mutator per `13§5` now actually holds.
    // CPL=0 reads from a validated user buffer into the per-task FPU slot.
    unsafe {
        let dst = (*target.fpu_state.get()).as_mut_ptr();
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
