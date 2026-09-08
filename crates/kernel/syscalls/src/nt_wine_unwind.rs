//! Wine builtin-ELF unwind dispatch for the NT personality.

// The Windows unwind implementation is executed only by the x86-64 NT
// personality. AArch64 builds compile this module for shared ABI coverage,
// but do not dispatch its machine-frame code.
#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]

#[path = "nt_wine_unwind/answer.rs"]
pub mod answer;
pub use answer::{unwind_status, UnwindRefusal};

const CONTEXT_RAX: u64 = 0x78;
const CONTEXT_RSP: u64 = 0x98;
const CONTEXT_RIP: u64 = 0xf8;
const DISPATCH_CONTROL_PC: u64 = 0;
const DISPATCH_IMAGE_BASE: u64 = 8;
const DISPATCH_ESTABLISHER_FRAME: u64 = 24;

#[cfg(target_os = "oxide-kernel")]
pub fn dispatch(args: u64) -> u64 { unwind_status(attempt(args)) }

#[cfg(target_os = "oxide-kernel")]
fn attempt(args: u64) -> Result<(), UnwindRefusal> {
    if args == 0 { return Err(UnwindRefusal::MalformedRequest); }
    let Ok(unwind_type) = uaccess::get_user_u32(args) else { return Err(UnwindRefusal::MalformedRequest); };
    if unwind_type & !7 != 0 { return Err(UnwindRefusal::MalformedRequest); }
    let Ok(dispatcher) = uaccess::get_user_u64(args + 8) else { return Err(UnwindRefusal::MalformedRequest); };
    let Ok(context) = uaccess::get_user_u64(args + 16) else { return Err(UnwindRefusal::MalformedRequest); };
    if dispatcher == 0 || context == 0 { return Err(UnwindRefusal::MalformedRequest); }
    let Some(cur) = sched::live::current() else { return Err(UnwindRefusal::NoCaller); };
    if !cur.is_nt_personality() { return Err(UnwindRefusal::NoCaller); }

    #[cfg(target_arch = "x86_64")]
    { unwind_x64(cur, dispatcher, context) }
    #[cfg(target_arch = "aarch64")]
    { let _ = (cur, dispatcher, context); Err(UnwindRefusal::UnsupportedMachine) }
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn dispatch(_args: u64) -> u64 { unwind_status(Err(UnwindRefusal::UnsupportedMachine)) }

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn unwind_x64(cur: &sched::Task, dispatcher: u64, context: u64) -> Result<(), UnwindRefusal> {
    let Some(mm) = cur.clone_mm() else { return Err(UnwindRefusal::NoCaller); };
    let Some(rip) = read(context, CONTEXT_RIP) else { return Err(UnwindRefusal::InaccessibleRecord); };
    let Some(module) = elf_load::elf_modules::find(mm.root_pa(), rip.saturating_sub(1)) else {
        return Err(UnwindRefusal::NoModule);
    };
    let Some(fde) = elf::find_fde(&module.eh_frame, module.eh_frame_address,
        rip.saturating_sub(1), elf::EhBases { text: module.base, data: module.base })
        .ok().flatten() else { return Err(UnwindRefusal::NoFrameDescription); };
    let Some(start) = fde.code_start else { return Err(UnwindRefusal::MalformedFrameProgram); };
    let Ok(program) = elf::frame_program(&module.eh_frame, &fde) else {
        return Err(UnwindRefusal::MalformedFrameProgram);
    };
    let mut registers = [0u64; 17];
    for (index, offset) in CONTEXT_OFFSETS.iter().enumerate() {
        let Some(value) = read(context, *offset) else { return Err(UnwindRefusal::InaccessibleRecord); };
        registers[index] = value;
    }
    let initial = elf::CfaContext { registers, cfa: 0 };
    let Some(target_delta) = rip.checked_sub(start) else { return Err(UnwindRefusal::MalformedFrameProgram); };
    let result = elf::evaluate_frame(&program, initial, target_delta,
        |address| uaccess::get_user_u64(address).ok());
    let Ok(result) = result else { return Err(UnwindRefusal::MalformedFrameProgram); };
    for (index, offset) in CONTEXT_OFFSETS.iter().enumerate() {
        let Some(address) = context.checked_add(*offset) else { return Err(UnwindRefusal::InaccessibleRecord); };
        if uaccess::put_user_u64(address, result.registers[index]).is_err() {
            return Err(UnwindRefusal::InaccessibleRecord);
        }
    }
    let Some(control_pc) = dispatcher.checked_add(DISPATCH_CONTROL_PC) else { return Err(UnwindRefusal::InaccessibleRecord); };
    let Some(image_base) = dispatcher.checked_add(DISPATCH_IMAGE_BASE) else { return Err(UnwindRefusal::InaccessibleRecord); };
    let Some(establisher) = dispatcher.checked_add(DISPATCH_ESTABLISHER_FRAME) else { return Err(UnwindRefusal::InaccessibleRecord); };
    if uaccess::put_user_u64(control_pc, rip).is_err()
        || uaccess::put_user_u64(image_base, module.base).is_err()
        || uaccess::put_user_u64(establisher, result.cfa).is_err() {
        return Err(UnwindRefusal::InaccessibleRecord);
    }
    Ok(())
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn read(base: u64, offset: u64) -> Option<u64> {
    base.checked_add(offset).and_then(|address| uaccess::get_user_u64(address).ok())
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
const CONTEXT_OFFSETS: [u64; 17] = [
    CONTEXT_RAX, 0x88, 0x80, 0x90, 0xa8, 0xb0, 0xa0, CONTEXT_RSP,
    0xb8, 0xc0, 0xc8, 0xd0, 0xd8, 0xe0, 0xe8, 0xf0, CONTEXT_RIP,
];
