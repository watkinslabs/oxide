//! Arm the Windows user exception dispatcher from scheduler-owned state.

#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

use crate::arch_frame::UserRegs;
use sched::nt_exception::context::{x64_context, x64_dispatch_rflags, x64_write_context_ex, x64_write_floating, X64Registers, X64_FLT_SAVE_BYTES};
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
unsafe fn capture(task: &sched::Task, regs: *const UserRegs) -> [u8; CONTEXT_BYTES] {
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
    let mut context = x64_context(&registers, hal_x86_64::USER_SS_SELECTOR as u16);
    task.debug_check_fpu_state("nt-exception-capture");
    let mut floating = [0u8; X64_FLT_SAVE_BYTES];
    // SAFETY: the running task owns its aligned FPU buffer on this CPU, and the save establishes the legacy image before it is copied out.
    unsafe {
        let state = (*task.security.fpu_state.get()).as_mut_ptr();
        hal_x86_64::fpu_save(state.cast::<hal_x86_64::FpuStateX86_64>());
        core::ptr::copy_nonoverlapping(state, floating.as_mut_ptr(), X64_FLT_SAVE_BYTES);
    }
    x64_write_floating(&mut context, &floating);
    context
}

/// Build and arm the x86-64 exception frame.
///
/// The pending record is consumed only after every user write and the live
/// return-frame rewrite succeed. A refusal is TERMINAL — the record is retired
/// and the thread group ends with the exception code, the way the reference
/// aborts a thread whose exception frame cannot be built. Re-arming the slot
/// instead is the livelock: the work loop re-runs this arm on every kernel
/// entry, refuses on the same input, and never converges (KI-0459).
///
/// The FAULTING PC is not validated. An instruction fetch from an unmapped or
/// non-executable address is exactly the access violation being reported, and
/// the only memory this pass must validate is the stack it writes and the
/// dispatcher entry it jumps to.
/// # SAFETY: `regs` is the live return-to-user frame; the task's address space is active.
/// # C: O(log N_vmas)
/// # Ctx: return-to-user
/// # Sleeps: yes — the user-frame write can fault
pub unsafe fn deliver(regs: *mut UserRegs) -> bool {
    let Some(task) = sched::live::current() else { return false; };
    if !task.is_nt_personality() { return false; }
    let Some(pending) = task.nt_exception.begin_delivery() else { return false; };
    // SAFETY: caller's contract — `regs` is this pass's live entry frame and no other consumer owns it.
    let mut context = match pending.context { Some(context) => context, None => unsafe { capture(&task, regs) } };
    let refuse = || refuse_delivery(&task, &pending.record);
    if !sched::nt_exception::prepare_dispatch_context(&pending.record, &mut context) { return refuse(); }
    let Ok(image) = crate::nt_context_image::decode(&context) else { return refuse(); };
    if image.validate_user_return(hal_x86_64::USER_CS_SELECTOR, hal_x86_64::USER_SS_SELECTOR).is_err() { return refuse(); }
    let Some(mm) = task.clone_mm() else { return refuse(); };
    let rip = image.registers[crate::nt_context_image::RestoreImage::RIP];
    let context_rsp = image.registers[crate::nt_context_image::RestoreImage::RSP];
    let Some(frame) = pe::nt_stub::x64_exception_frame(context_rsp, 0) else { return refuse(); };
    let writable = hal::UserVirtAddr::new(frame.stack).and_then(|address| mm.find_vma(address))
        .is_some_and(|stack| pe::nt_stub::valid_x64_exception_frame_range(frame.stack, stack.start.as_u64(),
                                                                         stack.end.as_u64(),
                                                                         stack.prot.contains(vmm::VmaProt::WRITE)));
    let dispatcher = crate::nt_loader_proc::module_base_by_name(&task, b"ntdll.dll")
        .and_then(|ntdll| crate::nt_loader_proc::resolve_exported_routine_by_name(&task, ntdll, b"KiUserExceptionDispatcher"));
    let Some(dispatcher) = decide(&task, &pending.record, writable, dispatcher) else { return false; };
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

/// Ask the one delivery decision whether this pass may enter the dispatcher,
/// and end the thread group when it may not.
///
/// `Some(entry)` is the resolved dispatcher; `None` means the group is exiting
/// and this pass has nothing left to do. Retiring the record before the exit
/// keeps the invariant the work loop depends on: no return from `deliver`
/// leaves a reservation armed.
/// # C: O(N_threads) on the terminal answer, O(1) otherwise
fn decide(task: &sched::Task, record: &[u8; sched::nt_exception::EXCEPTION_RECORD_BYTES],
          writable: bool, dispatcher: Option<u64>) -> Option<u64> {
    match sched::nt_exception::delivery_outcome(record, writable, dispatcher) {
        sched::nt_exception::Disposition::Dispatch => dispatcher,
        sched::nt_exception::Disposition::Terminate(status) => {
            let _ = task.nt_exception.fail_delivery();
            let _ = crate::s060_exit::do_group_exit(status);
            None
        }
    }
}

/// Terminal answer for a refusal that never reached the resolved-memory
/// decision: a malformed context, no address space, or a user-frame write
/// that faulted. The reference has no recoverable arm here either.
/// # C: O(N_threads)
fn refuse_delivery(task: &sched::Task, record: &[u8; sched::nt_exception::EXCEPTION_RECORD_BYTES]) -> bool {
    let _ = decide(task, record, false, None);
    false
}

/// `CONTEXT.EFlags`, whose value the machine frame reports unchanged: the
/// frame describes the INTERRUPTED thread, not the dispatcher's own state.
const EFLAGS_OFFSET: usize = 0x44;
