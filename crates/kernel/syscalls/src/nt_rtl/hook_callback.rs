//! Enter a Windows hook procedure. A window hook takes the filter code, the
//! wParam and the lParam, returning through the window-procedure continuation.
//! WinEvent hooks use the client callback table and its module resolution.
use super::*;

#[cfg(target_arch = "x86_64")]
mod frame {
    /// Return address plus the four shadow slots the Windows ABI reserves.
    pub(super) const BASE_SLOTS: u64 = 5;
    /// The frame is padded so the callee sees the stack alignment a call leaves.
    pub(super) const ALIGNMENT_REMAINDER: u64 = 8;
    /// First stack argument slot, past the return address and the shadow store.
    pub(super) const FIRST_STACK_SLOT: u64 = 5;
}

/// Build the callback frame and enter `hook_proc` with `registers` in
/// RCX/RDX/R8/R9 and `stack` in the argument slots past the shadow store.
/// # C: O(N_stack_arguments)
#[cfg(target_arch = "x86_64")]
fn begin(registers: [u64; 4], stack: &[u64], hook_proc: u64) -> u64 {
    if hook_proc == 0 || !uaccess::access_ok(hook_proc, 1) { return STATUS_INVALID_PARAMETER; }
    let Some(task) = sched::live::current().filter(|task| task.is_nt_personality()) else { return STATUS_INVALID_PARAMETER; };
    let Some(continuation) = crate::nt_loader_proc::support_root(task)
        .and_then(elf_load::pe_loader::nt_support::wndproc_continuation) else { return STATUS_INVALID_PARAMETER; };
    let regs = hal_x86_64::current_pt_regs();
    if regs.is_null() { return STATUS_INVALID_PARAMETER; }
    let pt = unsafe { &mut *regs };
    let slots = frame::BASE_SLOTS + stack.len() as u64;
    let bytes = (slots * 8 + 0xf) & !0xf;
    let mut callback_rsp = pt.rsp.checked_sub(bytes).unwrap_or(0);
    if callback_rsp == 0 { return STATUS_INVALID_PARAMETER; }
    if callback_rsp & 0xf != frame::ALIGNMENT_REMAINDER {
        callback_rsp = callback_rsp.checked_sub(8).unwrap_or(0);
        if callback_rsp == 0 || callback_rsp & 0xf != frame::ALIGNMENT_REMAINDER { return STATUS_INVALID_PARAMETER; }
    }
    for slot in 1..frame::BASE_SLOTS { if uaccess::put_user_u64(callback_rsp + slot * 8, 0).is_err() { return STATUS_INVALID_PARAMETER; } }
    for (index, value) in stack.iter().enumerate() {
        let Some(address) = callback_rsp.checked_add((frame::FIRST_STACK_SLOT + index as u64) * 8) else { return STATUS_INVALID_PARAMETER; };
        if uaccess::put_user_u64(address, *value).is_err() { return STATUS_INVALID_PARAMETER; }
    }
    if uaccess::put_user_u64(callback_rsp, continuation).is_err() { return STATUS_INVALID_PARAMETER; }
    let continuation_frame = crate::nt_callback_frame::capture(pt, task, sched::nt_callback::Completion::NONE);
    if !task.nt_callback_stack.lock().push(continuation_frame) { return STATUS_INVALID_PARAMETER; }
    pt.rip = hook_proc;
    pt.rsp = callback_rsp;
    pt.rcx = registers[0];
    pt.rdx = registers[1];
    pt.r8 = registers[2];
    pt.r9 = registers[3];
    STATUS_PENDING
}

/// Enter a window hook procedure. # C: O(1)
#[cfg(target_arch = "x86_64")]
pub(crate) fn begin_hook_callback(code: u64, wparam: u64, lparam: u64, hook_proc: u64) -> u64 {
    begin([code, wparam, lparam, 0], &[], hook_proc)
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn begin_hook_callback(_: u64, _: u64, _: u64, _: u64) -> u64 { STATUS_NOT_SUPPORTED }
