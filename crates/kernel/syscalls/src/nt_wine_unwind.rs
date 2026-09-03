//! Wine builtin-ELF unwind dispatch for the NT personality.

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_UNSUCCESSFUL: u64 = 0xc000_0001;
const STATUS_INVALID_DISPOSITION: u64 = 0xc000_0026;
const CONTEXT_RAX: u64 = 0x78;
const CONTEXT_RSP: u64 = 0x98;
const CONTEXT_RIP: u64 = 0xf8;
const DISPATCH_CONTROL_PC: u64 = 0;
const DISPATCH_IMAGE_BASE: u64 = 8;
const DISPATCH_ESTABLISHER_FRAME: u64 = 24;

#[cfg(target_os = "oxide-kernel")]
pub fn dispatch(args: u64) -> u64 {
    if args == 0 { return STATUS_INVALID_PARAMETER; }
    let Ok(unwind_type) = uaccess::get_user_u32(args) else { return STATUS_INVALID_PARAMETER; };
    if unwind_type & !7 != 0 { return STATUS_INVALID_PARAMETER; }
    let Ok(dispatcher) = uaccess::get_user_u64(args + 8) else { return STATUS_INVALID_PARAMETER; };
    let Ok(context) = uaccess::get_user_u64(args + 16) else { return STATUS_INVALID_PARAMETER; };
    if dispatcher == 0 || context == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }

    #[cfg(target_arch = "x86_64")]
    { unwind_x64(cur, dispatcher, context) }
    #[cfg(target_arch = "aarch64")]
    { let _ = (cur, dispatcher, context); STATUS_UNSUCCESSFUL }
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn dispatch(_args: u64) -> u64 { STATUS_INVALID_PARAMETER }

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn unwind_x64(cur: &sched::Task, dispatcher: u64, context: u64) -> u64 {
    let Some(mm) = cur.clone_mm() else { return STATUS_UNSUCCESSFUL; };
    let Some(rip) = read(context, CONTEXT_RIP) else { return STATUS_INVALID_PARAMETER; };
    let Some(module) = elf_load::elf_modules::find(mm.root_pa(), rip.saturating_sub(1)) else {
        return STATUS_UNSUCCESSFUL;
    };
    let Some(fde) = elf::find_fde(&module.eh_frame, module.eh_frame_address,
        rip.saturating_sub(1), elf::EhBases { text: module.base, data: module.base })
        .ok().flatten() else { return STATUS_UNSUCCESSFUL; };
    let Some(start) = fde.code_start else { return STATUS_INVALID_DISPOSITION; };
    let Ok(program) = elf::frame_program(&module.eh_frame, &fde) else {
        return STATUS_INVALID_DISPOSITION;
    };
    let mut registers = [0u64; 17];
    for (index, offset) in CONTEXT_OFFSETS.iter().enumerate() {
        let Some(value) = read(context, *offset) else { return STATUS_INVALID_PARAMETER; };
        registers[index] = value;
    }
    let initial = elf::CfaContext { registers, cfa: 0 };
    let Some(target_delta) = rip.checked_sub(start) else { return STATUS_UNSUCCESSFUL; };
    let result = elf::evaluate_frame(&program, initial, target_delta,
        |address| uaccess::get_user_u64(address).ok());
    let Ok(result) = result else { return STATUS_UNSUCCESSFUL; };
    for (index, offset) in CONTEXT_OFFSETS.iter().enumerate() {
        let Some(address) = context.checked_add(*offset) else { return STATUS_INVALID_PARAMETER; };
        if uaccess::put_user_u64(address, result.registers[index]).is_err() {
            return STATUS_INVALID_PARAMETER;
        }
    }
    let Some(control_pc) = dispatcher.checked_add(DISPATCH_CONTROL_PC) else { return STATUS_INVALID_PARAMETER; };
    let Some(image_base) = dispatcher.checked_add(DISPATCH_IMAGE_BASE) else { return STATUS_INVALID_PARAMETER; };
    let Some(establisher) = dispatcher.checked_add(DISPATCH_ESTABLISHER_FRAME) else { return STATUS_INVALID_PARAMETER; };
    if uaccess::put_user_u64(control_pc, rip).is_err()
        || uaccess::put_user_u64(image_base, module.base).is_err()
        || uaccess::put_user_u64(establisher, result.cfa).is_err() {
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
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
