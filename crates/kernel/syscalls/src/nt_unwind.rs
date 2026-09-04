//! Native x86-64 transfer for the first Wine `RtlUnwind` boundary.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};
use elf_load::pe_modules;

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
#[cfg(target_arch = "x86_64")]
const STATUS_INVALID_UNWIND_TARGET: u64 = 0xc000_0028;
#[cfg(target_arch = "x86_64")]
const STATUS_NOT_SUPPORTED: u64 = 0xc000_00bb;
#[cfg(target_arch = "x86_64")]
const CONTEXT_BYTES: usize = 0x4d0;
#[cfg(target_arch = "x86_64")]
const CONTEXT_FLAGS_FULL: u32 = 0x0010_000f;

/// Apply the non-local return described by the x64 `RtlUnwind` ABI.
/// # C: O(1) plus one user read
pub fn dispatch(call: NtCall) -> Option<u64> {
    if matches!(call.service, NtService::RtlCaptureContext | NtService::RtlRestoreContext | NtService::NtContinue) {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
        if call.service == NtService::RtlCaptureContext { return Some(capture_context(&cur, call.args.a0)); }
        if call.service == NtService::NtContinue && call.args.a1 > 1 { return Some(STATUS_INVALID_PARAMETER); }
        return Some(restore_context(&cur, call.args.a0,
            call.service == NtService::NtContinue && call.args.a1 != 0));
    }
    if call.service == NtService::RtlLookupFunctionEntry { return Some(lookup_function_entry(call.args.a0, call.args.a1)); }
    if call.service == NtService::RtlPcToFileHeader { return Some(pc_to_file_header(call.args.a0, call.args.a1)); }
    if call.service == NtService::Setjmp || call.service == NtService::Setjmpex { return Some(setjmp(call.args.a0, call.args.a1)); }
    if call.service == NtService::Longjmp { return Some(longjmp(call.args.a0, call.args.a1 as u32)); }
    if call.service != NtService::RtlUnwind && call.service != NtService::RtlUnwindEx { return None; }
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
        // Windows reports an invalid unwind target when the requested end
        // frame precedes the active user stack; do this before rewriting any
        // part of the live return context.
        // SAFETY: current_pt_regs is the live syscall frame owned by this
        // running task; this read occurs before the transfer commit.
        let current_rsp = unsafe { (*regs).rsp };
        if !pe::nt_stub::valid_x64_unwind_target(current_rsp, frame) {
            return Some(STATUS_INVALID_UNWIND_TARGET);
        }
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

fn lookup_function_entry(pc: u64, base: u64) -> u64 {
    if base == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    if uaccess::put_user_u64(base, 0).is_err() { return STATUS_INVALID_PARAMETER; }
    let Some(mm) = cur.clone_mm() else { return 0; };
    let Some(module) = pe_modules::find(mm.root_pa(), pc) else { return 0; };
    if uaccess::put_user_u64(base, module.base).is_err() { return STATUS_INVALID_PARAMETER; }
    pe_modules::find_exception(mm.root_pa(), pc).unwrap_or(0)
}

fn pc_to_file_header(pc: u64, address: u64) -> u64 {
    if address == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let module = cur.clone_mm().and_then(|mm| pe_modules::find(mm.root_pa(), pc));
    let file_header = module.map_or(0, |module| module.base);
    if uaccess::put_user_u64(address, file_header).is_err() { return STATUS_INVALID_PARAMETER; }
    file_header
}

fn setjmp(buffer: u64, frame: u64) -> u64 {
    if buffer == 0 || hal::UserVirtAddr::new(buffer).is_none() { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    #[cfg(target_arch = "x86_64")]
    {
        let regs = hal_x86_64::current_pt_regs();
        if regs.is_null() { return STATUS_INVALID_PARAMETER; }
        // SAFETY: current_pt_regs is the active task frame and is exclusively read during dispatch.
        let regs = unsafe { &*regs };
        let mut jump = [0u8; 0x100];
        let put = |offset: usize, value: u64, out: &mut [u8; 0x100]| { out[offset..offset + 8].copy_from_slice(&value.to_le_bytes()); };
        put(0x00, frame, &mut jump); put(0x08, regs.rbx, &mut jump); put(0x10, regs.rsp, &mut jump);
        put(0x18, regs.rbp, &mut jump); put(0x20, regs.rsi, &mut jump); put(0x28, regs.rdi, &mut jump);
        put(0x30, regs.r12, &mut jump); put(0x38, regs.r13, &mut jump); put(0x40, regs.r14, &mut jump);
        put(0x48, regs.r15, &mut jump); put(0x50, regs.rip, &mut jump);
        if uaccess::copy_to_user(buffer, &jump).is_err() { return STATUS_INVALID_PARAMETER; }
        return 0;
    }
    #[cfg(target_arch = "aarch64")]
    { let _ = frame; STATUS_INVALID_PARAMETER }
}

fn longjmp(buffer: u64, value: u32) -> u64 {
    if buffer == 0 || hal::UserVirtAddr::new(buffer).is_none() { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    #[cfg(target_arch = "x86_64")]
    {
        let mut jump = [0u8; 0x100];
        if uaccess::copy_from_user(&mut jump, buffer).is_err() { return STATUS_INVALID_PARAMETER; }
        let read = |offset: usize| u64::from_le_bytes(jump[offset..offset + 8].try_into().unwrap());
        let rsp = read(0x10); let rip = read(0x50);
        if hal::UserVirtAddr::new(rsp).is_none() || hal::UserVirtAddr::new(rip).is_none() { return STATUS_INVALID_PARAMETER; }
        let regs = hal_x86_64::current_pt_regs();
        if regs.is_null() { return STATUS_INVALID_PARAMETER; }
        // SAFETY: current_pt_regs is the active task frame and is exclusively rewritten during this native dispatch transfer.
        let regs = unsafe { &mut *regs };
        regs.rbx = read(0x08); regs.rbp = read(0x18); regs.rsi = read(0x20); regs.rdi = read(0x28);
        regs.r12 = read(0x30); regs.r13 = read(0x38); regs.r14 = read(0x40); regs.r15 = read(0x48);
        regs.rsp = rsp; regs.rip = rip; regs.rax = if value == 0 { 1 } else { value as u64 };
        return regs.rax;
    }
    #[cfg(target_arch = "aarch64")]
    { let _ = value; STATUS_INVALID_PARAMETER }
}

fn restore_context(current: &sched::Task, target: u64, test_alert: bool) -> u64 {
    if target == 0 || hal::UserVirtAddr::new(target).is_none() { return STATUS_INVALID_PARAMETER; }
    #[cfg(target_arch = "x86_64")]
    {
        let mut bytes = [0u8; CONTEXT_BYTES];
        if uaccess::copy_from_user(&mut bytes, target).is_err() { return STATUS_INVALID_PARAMETER; }
        let image = match crate::nt_context_image::decode(&bytes) {
            Ok(image) => image,
            Err(crate::nt_context_image::Error::Invalid) => return STATUS_INVALID_PARAMETER,
            Err(crate::nt_context_image::Error::Unsupported) => return STATUS_NOT_SUPPORTED,
        };
        let rip = image.registers[crate::nt_context_image::RestoreImage::RIP];
        let rsp = image.registers[crate::nt_context_image::RestoreImage::RSP];
        if hal::UserVirtAddr::new(rip).is_none() || hal::UserVirtAddr::new(rsp).is_none() { return STATUS_INVALID_PARAMETER; }
        if let Some(floating) = &image.floating {
            let mxcsr = u32::from_le_bytes(floating[24..28].try_into().unwrap());
            if mxcsr & !hal_x86_64::mxcsr_feature_mask() != 0 { return STATUS_INVALID_PARAMETER; }
        }
        let frame = hal_x86_64::current_pt_regs();
        if frame.is_null() { return STATUS_INVALID_PARAMETER; }
        // SAFETY: the active syscall frame and current task FPU image are
        // single-owner state while this task executes the native syscall.
        let regs = unsafe { &mut *frame };
        if image.has_integer() {
            regs.rax = image.registers[crate::nt_context_image::RestoreImage::RAX];
            regs.rcx = image.registers[crate::nt_context_image::RestoreImage::RCX];
            regs.rdx = image.registers[crate::nt_context_image::RestoreImage::RDX];
            regs.rbx = image.registers[crate::nt_context_image::RestoreImage::RBX];
            regs.rbp = image.registers[crate::nt_context_image::RestoreImage::RBP];
            regs.rsi = image.registers[crate::nt_context_image::RestoreImage::RSI];
            regs.rdi = image.registers[crate::nt_context_image::RestoreImage::RDI];
            regs.r8 = image.registers[crate::nt_context_image::RestoreImage::R8];
            regs.r9 = image.registers[crate::nt_context_image::RestoreImage::R9];
            regs.r10 = image.registers[crate::nt_context_image::RestoreImage::R10];
            regs.r11 = image.registers[crate::nt_context_image::RestoreImage::R11];
            regs.r12 = image.registers[crate::nt_context_image::RestoreImage::R12];
            regs.r13 = image.registers[crate::nt_context_image::RestoreImage::R13];
            regs.r14 = image.registers[crate::nt_context_image::RestoreImage::R14];
            regs.r15 = image.registers[crate::nt_context_image::RestoreImage::R15];
        }
        if let Some(floating) = image.floating {
            current.debug_check_fpu_state("nt-continue");
            // SAFETY: current owns this aligned FPU buffer on this CPU; save
            // establishes the XSAVE header before the legacy image is replaced.
            unsafe {
                let state = (*current.security.fpu_state.get()).as_mut_ptr();
                hal_x86_64::fpu_save(state.cast::<hal_x86_64::FpuStateX86_64>());
                core::ptr::copy_nonoverlapping(floating.as_ptr(), state, floating.len());
                hal_x86_64::fpu_restore(state.cast::<hal_x86_64::FpuStateX86_64>());
            }
        }
        regs.rip = rip; regs.rsp = rsp;
        regs.rflags = hal::uregs::x86_64::sigreturn_eflags(regs.rflags, image.rflags as u64);
        if test_alert { current.nt_apc_queue.request_delivery(); }
        regs.rax
    }
    #[cfg(target_arch = "aarch64")]
    { let _ = (current, test_alert); STATUS_INVALID_PARAMETER }
}

fn capture_context(current: &sched::Task, target: u64) -> u64 {
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
        current.debug_check_fpu_state("nt-capture-context");
        // SAFETY: current owns this aligned FPU buffer while executing on this
        // CPU; the saved legacy region is copied before user memory is touched.
        unsafe {
            let state = (*current.security.fpu_state.get()).as_mut_ptr();
            hal_x86_64::fpu_save(state.cast::<hal_x86_64::FpuStateX86_64>());
            core::ptr::copy_nonoverlapping(state, context[0x100..0x300].as_mut_ptr(), 512);
        }
        let mxcsr: [u8; 4] = context[0x118..0x11c].try_into().unwrap();
        context[0x34..0x38].copy_from_slice(&mxcsr);
        if uaccess::copy_to_user(target, &context).is_err() { return STATUS_INVALID_PARAMETER; }
        return 0;
    }
    #[cfg(target_arch = "aarch64")]
    { let _ = current; STATUS_INVALID_PARAMETER }
}
