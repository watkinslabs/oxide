//! Enter one user-mode callback from the client's published callback table.
//! The Windows client ABI passes the argument block and its length; the
//! callback answers through NtCallbackReturn, which restores this frame.
use super::*;
use crate::nt_user_callback::{entry_pointer, peb_pointer, table_pointer};

/// Resolve one callback entry of the calling process. Zero when user32 has
/// published no table, or the entry itself is null.
/// # C: O(1) plus bounded usercopy
pub(crate) fn routine_for_current(index: u32) -> Option<u64> {
    let task = sched::live::current().filter(|task| task.is_nt_personality())?;
    let peb = uaccess::get_user_u64(peb_pointer(task.nt_teb())?).ok()?;
    let table = uaccess::get_user_u64(table_pointer(peb)?).ok()?;
    let routine = uaccess::get_user_u64(entry_pointer(table, index)?).ok()?;
    (routine != 0 && uaccess::access_ok(routine, 1)).then_some(routine)
}

/// Transfer the active NT syscall frame into one callback-table routine.
/// # C: O(1) plus bounded usercopy
#[cfg(target_arch = "x86_64")]
pub(crate) fn begin(index: u32, args: u64, length: u32, completion: sched::nt_callback::Completion) -> u64 {
    const SHADOW_SLOTS: u64 = 4;
    const FRAME_BYTES: u64 = 48;
    let Some(routine) = routine_for_current(index) else {
        klog::write_raw(b"[WINDOWS-USER-CALLBACK-REJECT] reason=no-routine index=");
        klog::write_hex_u64(index as u64); klog::write_raw(b"\n");
        return STATUS_INVALID_PARAMETER;
    };
    let Some(task) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    let ntdll = crate::nt_loader_proc::module_base_by_name(&task, b"ntdll.dll").unwrap_or(0);
    let Some(continuation) = elf_load::pe_loader::resolve_nt_runtime_wndproc_continuation(ntdll) else { return STATUS_INVALID_PARAMETER; };
    let regs = hal_x86_64::current_pt_regs();
    if regs.is_null() { return STATUS_INVALID_PARAMETER; }
    // SAFETY: the live NT syscall frame of the calling thread, retargeted at
    // the callback routine before returning to user mode.
    let frame = unsafe { &mut *regs };
    let callback_rsp = frame.rsp.checked_sub(FRAME_BYTES).unwrap_or(0);
    if callback_rsp == 0 || callback_rsp & 0xf != 8 { return STATUS_INVALID_PARAMETER; }
    for slot in 0..SHADOW_SLOTS { if uaccess::put_user_u64(callback_rsp + 8 + slot * 8, 0).is_err() { return STATUS_INVALID_PARAMETER; } }
    if uaccess::put_user_u64(callback_rsp, continuation).is_err() { return STATUS_INVALID_PARAMETER; }
    let saved = crate::nt_callback_frame::capture(frame, task, completion);
    if !task.nt_callback_stack.lock().push(saved) { return STATUS_INVALID_PARAMETER; }
    frame.rip = routine;
    frame.rsp = callback_rsp;
    frame.rcx = args;
    frame.rdx = length as u64;
    klog::write_raw(b"[WINDOWS-USER-CALLBACK-ENTER] index=");
    klog::write_hex_u64(index as u64); klog::write_raw(b" routine=");
    klog::write_hex_u64(routine); klog::write_raw(b"\n");
    STATUS_PENDING
}

/// The callback continuation has an AMD64 instruction ABI; never branch an
/// ARM user frame into it.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn begin(_: u32, _: u64, _: u32, _: sched::nt_callback::Completion) -> u64 { STATUS_NOT_SUPPORTED }
