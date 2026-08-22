/// Capture x86 parent syscall state and build the child's resume frame.
#[cfg(target_arch = "x86_64")]
pub(super) fn clone_spawn_arch(
    child_tid: u32, child_stack: u64,
    child_mm: alloc::sync::Arc<vmm::AddressSpace>,
    thread_group: Option<alloc::sync::Arc<sched::thread_group::ThreadGroup>>,
) -> Result<alloc::sync::Arc<sched::Task>, sched::live::spawn::SpawnError> {
    let regs = hal_x86_64::current_pt_regs();
    if regs.is_null() { return Err(sched::live::spawn::SpawnError::NoRunqueue); }
    // SAFETY: the running parent's saved syscall frame remains task-owned.
    let frame = unsafe { &*regs };
    let user_rsp = if child_stack != 0 { child_stack } else { frame.rsp };
    let pregs = hal_x86_64::ForkRegs {
        rdi: frame.rdi, rsi: frame.rsi, rdx: frame.rdx,
        r10: frame.r10, r8: frame.r8, r9: frame.r9, rcx: frame.rcx,
        r11: frame.r11, r12: frame.r12, rbx: frame.rbx, rbp: frame.rbp,
        r13: frame.r13, r14: frame.r14, r15: frame.r15,
    };
    sched::cputime_trace::clone_frame(child_tid, frame.rip, user_rsp, frame.rflags);
    // SAFETY: child is unpublished; address space and captured frame are complete.
    unsafe { sched::live::spawn_user_thread_for_fork(
        child_tid, "fork-child", frame.rip, user_rsp, frame.rflags,
        &pregs, child_mm, thread_group,
    ) }
}

/// Capture ARM parent SVC state and build the child's resume frame.
#[cfg(target_arch = "aarch64")]
pub(super) fn clone_spawn_arch(
    child_tid: u32, child_stack: u64,
    child_mm: alloc::sync::Arc<vmm::AddressSpace>,
    thread_group: Option<alloc::sync::Arc<sched::thread_group::ThreadGroup>>,
) -> Result<alloc::sync::Arc<sched::Task>, sched::live::spawn::SpawnError> {
    // SAFETY: the task-owned pointer remains tied to this parent across SVC.
    let svc = unsafe { &*crate::arch_frame::current_svc_frame() };
    let mut pregs = hal_aarch64::ForkRegs::default();
    for i in 0..18 { pregs.x[i] = svc.gp[i]; }
    pregs.x[18] = svc.x18_x29[0];
    pregs.x[29] = svc.x18_x29[1];
    pregs.x[30] = svc.x30;
    pregs.elr_el1 = svc.elr_el1;
    pregs.spsr_el1 = svc.spsr_el1;
    pregs.sp_el0 = svc.sp_el0;
    for i in 0..10 { pregs.x[19 + i] = svc.x19_x28[i]; }
    let user_sp = if child_stack != 0 { child_stack } else { pregs.sp_el0 };
    let user_ip = pregs.elr_el1;
    sched::cputime_trace::clone_frame(child_tid, user_ip, user_sp, pregs.spsr_el1);
    // SAFETY: child is unpublished; address space and captured frame are complete.
    unsafe { sched::live::spawn_user_thread_for_fork(
        child_tid, "fork-child", user_ip, user_sp, &pregs, child_mm,
        thread_group,
    ) }
}
