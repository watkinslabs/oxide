//! Native x86-64 transfer for the first Wine `RtlUnwind` boundary.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
#[cfg(target_arch = "x86_64")]
const CONTEXT_BYTES: usize = 0x4d0;
#[cfg(target_arch = "x86_64")]
const CONTEXT_FLAGS_FULL: u32 = 0x0010_000f;

/// Apply the non-local return described by the x64 `RtlUnwind` ABI.
/// # C: O(1) plus one user read
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlCaptureContext { return Some(capture_context(call.args.a0)); }
    if call.service == NtService::RtlRestoreContext { return Some(restore_context(call.args.a0)); }
    if call.service != NtService::RtlUnwind { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    #[cfg(target_arch = "x86_64")]
    {
        let frame = call.args.a0;
        let target_ip = call.args.a1;
        let return_value = call.args.a3;
        if frame == 0 || hal::UserVirtAddr::new(frame).is_none() || hal::UserVirtAddr::new(target_ip).is_none() {
            return Some(STATUS_INVALID_PARAMETER);
        }
        let return_address = match uaccess::get_user_u64(frame) {
            Ok(address) if hal::UserVirtAddr::new(address).is_some() => address,
            _ => return Some(STATUS_INVALID_PARAMETER),
        };
        let Some(rsp) = frame.checked_add(8).and_then(hal::UserVirtAddr::new) else {
            return Some(STATUS_INVALID_PARAMETER);
        };
        let regs = hal_x86_64::current_pt_regs();
        if regs.is_null() { return Some(STATUS_INVALID_PARAMETER); }
        // SAFETY: current_pt_regs is the live syscall frame owned by this
        // running task; RtlUnwind replaces its user return state atomically.
        let regs = unsafe { &mut *regs };
        regs.rip = target_ip;
        regs.rsp = rsp.as_u64();
        regs.rax = return_value;
        let _ = return_address;
        Some(return_value)
    }
    #[cfg(target_arch = "aarch64")]
    { let _ = cur; Some(STATUS_INVALID_PARAMETER) }
}

fn restore_context(target: u64) -> u64 {
    if target == 0 || hal::UserVirtAddr::new(target).is_none() { return STATUS_INVALID_PARAMETER; }
    #[cfg(target_arch = "x86_64")]
    {
        const RIP: u64 = 0xf8; const RSP: u64 = 0x98; const RFLAGS: u64 = 0x44;
        let read = |offset: u64| target.checked_add(offset).and_then(|address| uaccess::get_user_u64(address).ok());
        let Some(rip) = read(RIP) else { return STATUS_INVALID_PARAMETER; };
        let Some(rsp) = read(RSP) else { return STATUS_INVALID_PARAMETER; };
        if hal::UserVirtAddr::new(rip).is_none() || hal::UserVirtAddr::new(rsp).is_none() { return STATUS_INVALID_PARAMETER; }
        let frame = hal_x86_64::current_pt_regs();
        if frame.is_null() { return STATUS_INVALID_PARAMETER; }
        // SAFETY: the active syscall frame belongs exclusively to this task during native dispatch.
        let regs = unsafe { &mut *frame };
        let pairs = [(0x80, &mut regs.rcx), (0x88, &mut regs.rdx), (0x90, &mut regs.rbx), (0xa0, &mut regs.rbp), (0xa8, &mut regs.rsi), (0xb0, &mut regs.rdi), (0xb8, &mut regs.r8), (0xc0, &mut regs.r9), (0xc8, &mut regs.r10), (0xd0, &mut regs.r11), (0xd8, &mut regs.r12), (0xe0, &mut regs.r13), (0xe8, &mut regs.r14), (0xf0, &mut regs.r15), (0x78, &mut regs.rax)];
        for (offset, slot) in pairs { let Some(value) = read(offset) else { return STATUS_INVALID_PARAMETER; }; *slot = value; }
        let Some(flags) = target.checked_add(RFLAGS).and_then(|address| uaccess::get_user_u32(address).ok()) else { return STATUS_INVALID_PARAMETER; };
        regs.rip = rip; regs.rsp = rsp; regs.rflags = hal::uregs::x86_64::sigreturn_eflags(regs.rflags, flags as u64);
        regs.rax
    }
    #[cfg(target_arch = "aarch64")]
    { STATUS_INVALID_PARAMETER }
}

fn capture_context(target: u64) -> u64 {
    if target == 0 || hal::UserVirtAddr::new(target).is_none() { return STATUS_INVALID_PARAMETER; }
    #[cfg(target_arch = "x86_64")]
    {
        let regs = hal_x86_64::current_pt_regs();
        if regs.is_null() { return STATUS_INVALID_PARAMETER; }
        // SAFETY: current_pt_regs is the active task's live syscall frame;
        // this dispatch reads it while the owning task is not concurrently run.
        let regs = unsafe { &*regs };
        let mut context = [0u8; CONTEXT_BYTES];
        context[0x30..0x34].copy_from_slice(&CONTEXT_FLAGS_FULL.to_le_bytes());
        context[0x34..0x38].copy_from_slice(&0x1f80u32.to_le_bytes());
        for (offset, value) in [(0x38, regs.cs), (0x3a, regs.cs), (0x3c, regs.cs), (0x3e, 0), (0x40, 0), (0x42, regs.ss)] {
            context[offset..offset + 2].copy_from_slice(&(value as u16).to_le_bytes());
        }
        context[0x44..0x48].copy_from_slice(&(regs.rflags as u32).to_le_bytes());
        for (offset, value) in [(0x80, regs.rcx), (0x88, regs.rdx), (0x90, regs.rbx), (0x98, regs.rsp), (0xa0, regs.rbp), (0xa8, regs.rsi), (0xb0, regs.rdi), (0xb8, regs.r8), (0xc0, regs.r9), (0xc8, regs.r10), (0xd0, regs.r11), (0xd8, regs.r12), (0xe0, regs.r13), (0xe8, regs.r14), (0xf0, regs.r15), (0xf8, regs.rip)] {
            context[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        if uaccess::copy_to_user(target, &context).is_err() { return STATUS_INVALID_PARAMETER; }
        return 0;
    }
    #[cfg(target_arch = "aarch64")]
    { STATUS_INVALID_PARAMETER }
}
