//! ARM WndProc usercopy and canonical Task continuation handoff.
#[path = "aarch64.rs"]
mod abi;
use sched::nt_callback::{Completion, Frame};

const INVALID: u64 = 0xc000_000d;
const RESULT_SPILL_BYTES: usize = 16;
const CONTINUATION_BYTES: usize = 44;

/// Publish the ARM callback frame only after all fallible copying succeeds.
/// # C: O(payload + relocations)
pub(crate) fn begin(hwnd: u64, message: u64, wparam: u64, wndproc: u64, bytes: &[u8],
    relocations: &[(usize, usize)], completion: Completion) -> Result<u64, u64> {
    if hwnd == 0 || wndproc == 0 { return Err(INVALID); }
    let task = sched::live::current().filter(|task| task.is_nt_personality()).ok_or(INVALID)?;
    // SAFETY: current Task retains its address space through callback preparation.
    let mm = (unsafe { task.mm_ref() }).ok_or(INVALID)?;
    let ntdll = crate::nt_loader_proc::module_base_by_name(task, b"ntdll.dll").ok_or(INVALID)?;
    let continuation = elf_load::pe_loader::resolve_nt_runtime_wndproc_continuation_arm(ntdll).ok_or(INVALID)?;
    for (address, length) in [(wndproc, 4), (continuation, CONTINUATION_BYTES)] {
        if address & 3 != 0 || !uaccess::access_ok(address, length) { return Err(INVALID); }
        for endpoint in [address, address.checked_add(length as u64 - 1).ok_or(INVALID)?] {
            let target = hal::UserVirtAddr::new(endpoint).ok_or(INVALID)?;
            if !mm.find_vma(target).is_some_and(|vma| vma.prot.contains(vmm::VmaProt::EXEC)) { return Err(INVALID); }
        }
    }
    let regs = hal_aarch64::current_svc_frame();
    if regs.is_null() { return Err(INVALID); }
    // SAFETY: active syscall frame belongs exclusively to this current Task.
    let frame = unsafe { &mut *regs };
    let saved = abi::Control { pc: frame.elr_el1, sp: frame.sp_el0, lr: frame.x30 };
    let payload = abi::prepare(saved.sp, bytes, relocations, hal::USER_VA_END).ok_or(INVALID)?;
    let handoff = abi::handoff(saved, &payload, wndproc, continuation, hwnd, message, wparam, hal::USER_VA_END).ok_or(INVALID)?;
    let spill = payload.stack.checked_sub(RESULT_SPILL_BYTES as u64).ok_or(INVALID)?;
    uaccess::copy_to_user(payload.address, &payload.bytes).map_err(|_| INVALID)?;
    uaccess::copy_to_user(spill, &[0; RESULT_SPILL_BYTES]).map_err(|_| INVALID)?;
    if !task.nt_callback_stack.lock().push(Frame { rip: saved.pc, rsp: saved.sp, lr: saved.lr, completion }) {
        return Err(INVALID);
    }
    frame.elr_el1 = handoff.entry.pc;
    frame.sp_el0 = handoff.entry.sp;
    frame.x30 = handoff.entry.lr;
    frame.gp[..4].copy_from_slice(&handoff.arguments);
    frame.retval = handoff.syscall_result;
    Ok(handoff.syscall_result)
}
