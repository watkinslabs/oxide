//! Native unhandled-exception filter state for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;
use sched::nt_exception::{Pending, CONTEXT_BYTES, EXCEPTION_RECORD_BYTES};
use syscall::nt::{NtCall, NtService};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_SUCCESS: u64 = 0;
const STATUS_UNSUCCESSFUL: u64 = 0xc000_0001;
const STATUS_NOT_SUPPORTED: u64 = 0xc000_00bb;
const EXCEPTION_NONCONTINUABLE: u32 = 1;
const EXCEPTION_CODE_OFFSET: usize = 0;
const EXCEPTION_FLAGS_OFFSET: usize = 4;
#[cfg(target_arch = "x86_64")]
const EXCEPTION_ADDRESS_OFFSET: usize = 16;

#[cfg(target_arch = "x86_64")]
fn capture_context() -> Option<[u8; CONTEXT_BYTES]> {
    let frame = hal_x86_64::current_pt_regs();
    if frame.is_null() { return None; }
    // SAFETY: the active syscall frame belongs exclusively to this running NT task while dispatch owns it.
    let frame = unsafe { &*frame };
    let mut context = [0u8; CONTEXT_BYTES];
    context[0x30..0x34].copy_from_slice(&0x0010_000f_u32.to_le_bytes());
    for (offset, value) in [(0x38, frame.cs), (0x42, frame.ss)] { context[offset..offset + 2].copy_from_slice(&(value as u16).to_le_bytes()); }
    context[0x44..0x48].copy_from_slice(&(frame.rflags as u32).to_le_bytes());
    for (offset, value) in [(0x78, frame.rax), (0x80, frame.rcx), (0x88, frame.rdx), (0x90, frame.rbx),
        (0x98, frame.rsp), (0xa0, frame.rbp), (0xa8, frame.rsi), (0xb0, frame.rdi), (0xb8, frame.r8),
        (0xc0, frame.r9), (0xc8, frame.r10), (0xd0, frame.r11), (0xd8, frame.r12), (0xe0, frame.r13),
        (0xe8, frame.r14), (0xf0, frame.r15), (0xf8, frame.rip)] {
        context[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    Some(context)
}

#[cfg(not(target_arch = "x86_64"))]
fn capture_context() -> Option<[u8; CONTEXT_BYTES]> { None }

fn publish(current: &sched::Task, record: [u8; EXCEPTION_RECORD_BYTES], mut context: [u8; CONTEXT_BYTES], first_chance: bool) -> u64 {
    if !sched::nt_exception::prepare_dispatch_context(&record, &mut context) { return STATUS_INVALID_PARAMETER; }
    current.nt_exception.publish(Pending { record, context, first_chance }).map_or(STATUS_UNSUCCESSFUL, |_| STATUS_SUCCESS)
}

#[cfg(target_arch = "x86_64")]
fn exception_dispatcher(current: &sched::Task) -> Option<u64> {
    let ntdll = crate::nt_loader_proc::module_base_by_name(current, b"ntdll.dll")?;
    crate::nt_loader_proc::resolve_exported_routine_by_name(current, ntdll, b"KiUserExceptionDispatcher")
}

#[cfg(not(target_arch = "x86_64"))]
fn exception_dispatcher(_current: &sched::Task) -> Option<u64> { None }

#[cfg(target_arch = "x86_64")]
fn raise_from_user(current: &sched::Task, record: u64, context: u64, first_chance: u64) -> u64 {
    if record == 0 || context == 0 || hal::UserVirtAddr::new(record).is_none() || hal::UserVirtAddr::new(context).is_none() || first_chance > 1 { return STATUS_INVALID_PARAMETER; }
    let mut record_bytes = [0u8; EXCEPTION_RECORD_BYTES];
    let mut context_bytes = [0u8; CONTEXT_BYTES];
    if uaccess::copy_from_user(&mut record_bytes, record).is_err() || uaccess::copy_from_user(&mut context_bytes, context).is_err() { return STATUS_INVALID_PARAMETER; }
    let image = match crate::nt_context_image::decode(&context_bytes) {
        Ok(image) => image,
        Err(crate::nt_context_image::Error::Invalid) => return STATUS_INVALID_PARAMETER,
        Err(crate::nt_context_image::Error::Unsupported) => return STATUS_NOT_SUPPORTED,
    };
    let rip = image.registers[crate::nt_context_image::RestoreImage::RIP];
    let rsp = image.registers[crate::nt_context_image::RestoreImage::RSP];
    if hal::UserVirtAddr::new(rip).is_none() || hal::UserVirtAddr::new(rsp).is_none()
        || image.rflags & 0x2 == 0 || image.rflags & 0x3000 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    publish(current, record_bytes, context_bytes, first_chance != 0)
}

pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlRaiseStatus {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
        if exception_dispatcher(&cur).is_none() { return Some(STATUS_UNSUCCESSFUL); }
        let Some(context) = capture_context() else { return Some(STATUS_INVALID_PARAMETER); };
        let mut record = [0u8; EXCEPTION_RECORD_BYTES];
        record[EXCEPTION_CODE_OFFSET..EXCEPTION_CODE_OFFSET + 4].copy_from_slice(&(call.args.a0 as u32).to_le_bytes());
        record[EXCEPTION_FLAGS_OFFSET..EXCEPTION_FLAGS_OFFSET + 4].copy_from_slice(&EXCEPTION_NONCONTINUABLE.to_le_bytes());
        #[cfg(target_arch = "x86_64")]
        {
            let frame = hal_x86_64::current_pt_regs();
            if !frame.is_null() {
                // SAFETY: the active syscall frame belongs exclusively to this running NT task during record construction.
                let frame = unsafe { &*frame };
                record[EXCEPTION_ADDRESS_OFFSET..EXCEPTION_ADDRESS_OFFSET + 8].copy_from_slice(&frame.rip.to_le_bytes());
            }
        }
        return Some(publish(&cur, record, context, true));
    }
    if call.service == NtService::RtlRaiseException {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 {
            return Some(STATUS_INVALID_PARAMETER);
        }
        if exception_dispatcher(&cur).is_none() { return Some(STATUS_UNSUCCESSFUL); }
        let Some(context) = capture_context() else { return Some(STATUS_INVALID_PARAMETER); };
        let mut record = [0u8; EXCEPTION_RECORD_BYTES];
        if uaccess::copy_from_user(&mut record, call.args.a0).is_err() { return Some(STATUS_INVALID_PARAMETER); }
        return Some(publish(&cur, record, context, true));
    }
    if call.service == NtService::NtRaiseException {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
        #[cfg(target_arch = "aarch64")]
        { return Some(STATUS_NOT_SUPPORTED); }
        #[cfg(target_arch = "x86_64")]
        {
            if exception_dispatcher(&cur).is_none() { return Some(STATUS_UNSUCCESSFUL); }
            return Some(raise_from_user(&cur, call.args.a0, call.args.a1, call.args.a2));
        }
    }
    if call.service != NtService::RtlSetUnhandledExceptionFilter { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() || (call.args.a0 != 0 && hal::UserVirtAddr::new(call.args.a0).is_none()) {
        return Some(STATUS_INVALID_PARAMETER);
    }
    cur.thread_group.nt_unhandled_filter.store(call.args.a0, Ordering::Release);
    Some(0)
}
