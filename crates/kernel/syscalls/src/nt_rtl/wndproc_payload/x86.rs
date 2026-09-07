use super::prepare;
use sched::nt_callback::Completion;
const INVALID: u64 = 0xc000_000d;

/// Own all payload bytes before redirecting the current PE frame. # C: O(payload)
pub(crate) fn begin(hwnd: u64, message: u64, wparam: u64, wndproc: u64, bytes: &[u8],
    relocations: &[(usize, usize)], completion: Completion) -> Result<u64, u64> {
    // Every other entry into a window procedure announces itself. Without this
    // one, a message delivered with a payload - the two nonclient size
    // calculations among them - looked from the trace like a message that was
    // never sent, and was twice read that way.
    klog::write_raw(b"[WINDOWS-WNDPROC-ENTER] hwnd=");
    klog::write_hex_u64(hwnd);
    klog::write_raw(b" msg=");
    klog::write_hex_u64(message);
    klog::write_raw(b" wndproc=");
    klog::write_hex_u64(wndproc);
    klog::write_raw(b" payload=1\n");
    if hwnd == 0 || wndproc == 0 { return Err(INVALID); }
    let task = sched::live::current().filter(|task| task.is_nt_personality()).ok_or(INVALID)?;
    // SAFETY: the current Task retains its address space during callback preparation.
    let mm = (unsafe { task.mm_ref() }).ok_or(INVALID)?;
    let target = hal::UserVirtAddr::new(wndproc).ok_or(INVALID)?;
    if !mm.find_vma(target).is_some_and(|vma| vma.prot.contains(vmm::VmaProt::EXEC)) { return Err(INVALID); }
    let ntdll = crate::nt_loader_proc::module_base_by_name(task, b"ntdll.dll").ok_or(INVALID)?;
    let continuation = elf_load::pe_loader::resolve_nt_runtime_wndproc_continuation(ntdll).ok_or(INVALID)?;
    let regs = hal_x86_64::current_pt_regs();
    if regs.is_null() { return Err(INVALID); }
    // SAFETY: this syscall exclusively owns the active Task's saved user register frame.
    let frame = unsafe { &mut *regs };
    let payload = prepare(frame.rsp, bytes, relocations).ok_or(INVALID)?;
    uaccess::copy_to_user(payload.address, &payload.bytes).map_err(|_| INVALID)?;
    let mut shadow = [0u8; 40]; shadow[..8].copy_from_slice(&continuation.to_le_bytes());
    uaccess::copy_to_user(payload.stack, &shadow).map_err(|_| INVALID)?;
    let saved = crate::nt_callback_frame::capture(frame, task, completion);
    if !task.nt_callback_stack.lock().push(saved) { return Err(INVALID); }
    frame.rip = wndproc; frame.rsp = payload.stack;
    frame.rcx = hwnd; frame.rdx = message; frame.r8 = wparam; frame.r9 = payload.address;
    Ok(payload.address)
}
