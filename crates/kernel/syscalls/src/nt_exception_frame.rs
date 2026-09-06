//! Arm the Windows user exception dispatcher from scheduler-owned state.

#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

use crate::arch_frame::UserRegs;
use sched::nt_exception::context::{x64_context, x64_dispatch_rflags, x64_write_context_ex, X64Registers};
use sched::nt_exception::CONTEXT_BYTES;

/// The interrupted register set the dispatcher frame reports.
///
/// A hardware trap publishes no context: the trap frame's per-CPU pointer is
/// not safe to dereference from the fault path once the resolver may have
/// switched tasks. This pass owns the live frame, so the capture happens
/// here — the same place the reference runtime reads its own saved frame when
/// it raises an exception out of a system call.
/// # SAFETY: `regs` is the live return-to-user frame owned by this pass.
/// # C: O(1)
unsafe fn capture(regs: *const UserRegs) -> [u8; CONTEXT_BYTES] {
    // SAFETY: the return-to-user loop owns this task's live entry frame for the duration of the delivery pass.
    let frame = unsafe { &*regs };
    let registers = X64Registers {
        rax: frame.rax, rcx: frame.rcx, rdx: frame.rdx, rbx: frame.rbx,
        rsp: frame.rsp, rbp: frame.rbp, rsi: frame.rsi, rdi: frame.rdi,
        r8: frame.r8, r9: frame.r9, r10: frame.r10, r11: frame.r11,
        r12: frame.r12, r13: frame.r13, r14: frame.r14, r15: frame.r15,
        rip: frame.rip, rflags: frame.rflags,
        cs: frame.cs as u16, ss: frame.ss as u16,
    };
    x64_context(&registers, hal_x86_64::USER_SS_SELECTOR as u16)
}

/// Build and arm the x86-64 exception frame.
///
/// The pending record is consumed only after every user write and the live
/// return-frame rewrite succeed; any refusal returns the reservation, and the
/// bounded work loop then resumes the faulting instruction, whose re-fault
/// finds the slot occupied and reports the POSIX signal instead.
/// # SAFETY: `regs` is the live return-to-user frame; the task's address space is active.
/// # C: O(log N_vmas)
/// # Ctx: return-to-user
/// # Sleeps: yes — the user-frame write can fault
pub unsafe fn deliver(regs: *mut UserRegs) -> bool {
    let Some(task) = sched::live::current() else { return false; };
    if !task.is_nt_personality() { return false; }
    let Some(pending) = task.nt_exception.begin_delivery() else { return false; };
    // SAFETY: caller's contract — `regs` is this pass's live entry frame and no other consumer owns it.
    let mut context = match pending.context { Some(context) => context, None => unsafe { capture(regs) } };
    let refuse = || { let _ = task.nt_exception.abort_delivery(); false };
    if !sched::nt_exception::prepare_dispatch_context(&pending.record, &mut context) { return refuse(); }
    let Ok(image) = crate::nt_context_image::decode(&context) else { return refuse(); };
    if image.validate_user_return(hal_x86_64::USER_CS_SELECTOR, hal_x86_64::USER_SS_SELECTOR).is_err() { return refuse(); }
    let Some(mm) = task.clone_mm() else { return refuse(); };
    let rip = image.registers[crate::nt_context_image::RestoreImage::RIP];
    let context_rsp = image.registers[crate::nt_context_image::RestoreImage::RSP];
    let Some(code) = hal::UserVirtAddr::new(rip).and_then(|address| mm.find_vma(address)) else { return refuse(); };
    if !code.prot.contains(vmm::VmaProt::EXEC) { return refuse(); }
    let Some(frame) = pe::nt_stub::x64_exception_frame(context_rsp, 0) else { return refuse(); };
    let Some(stack) = hal::UserVirtAddr::new(frame.stack).and_then(|address| mm.find_vma(address)) else { return refuse(); };
    if !pe::nt_stub::valid_x64_exception_frame_range(frame.stack, stack.start.as_u64(), stack.end.as_u64(),
                                                     stack.prot.contains(vmm::VmaProt::WRITE)) { return refuse(); }
    let Some(ntdll) = crate::nt_loader_proc::module_base_by_name(&task, b"ntdll.dll") else { return refuse(); };
    let Some(dispatcher) = crate::nt_loader_proc::resolve_exported_routine_by_name(&task, ntdll, b"KiUserExceptionDispatcher") else { return refuse(); };
    let mut user_frame = [0u8; pe::nt_stub::X64_EXCEPTION_FRAME_BYTES as usize];
    user_frame[..context.len()].copy_from_slice(&context);
    if !x64_write_context_ex(&mut user_frame) { return refuse(); }
    let record_at = pe::nt_stub::X64_EXCEPTION_RECORD_OFFSET as usize;
    user_frame[record_at..record_at + pending.record.len()].copy_from_slice(&pending.record);
    let rflags = u64::from(u32::from_le_bytes(context[EFLAGS_OFFSET..EFLAGS_OFFSET + 4].try_into().unwrap()));
    for (offset, value) in [(0u64, rip), (8, hal_x86_64::USER_CS_SELECTOR), (16, rflags),
                            (24, context_rsp), (32, hal_x86_64::USER_SS_SELECTOR)] {
        let offset = pe::nt_stub::X64_EXCEPTION_MACHINE_FRAME_OFFSET as usize + offset as usize;
        user_frame[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    if uaccess::copy_to_user(frame.stack, &user_frame).is_err() { return refuse(); }
    // SAFETY: the return frame is the active entry frame owned by this task; every user frame write completed above.
    let regs = unsafe { &mut *regs };
    regs.rip = dispatcher;
    regs.rsp = frame.stack;
    regs.rflags = x64_dispatch_rflags(regs.rflags);
    let _ = task.nt_exception.complete_delivery();
    true
}

/// `CONTEXT.EFlags`, whose value the machine frame reports unchanged: the
/// frame describes the INTERRUPTED thread, not the dispatcher's own state.
const EFLAGS_OFFSET: usize = 0x44;
