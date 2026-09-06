//! Delay-load thunk binding: descriptor walk, export resolution, IAT publish,
//! and the failure-hook control transfer.

use alloc::vec::Vec;

use crate::nt_delay_load_policy as policy;
use policy::{DelayDescriptor, FailureTarget, ImportSelector};

/// The service answers with an address, never a status: the delay-load thunk
/// jumps to whatever it returns.
const NO_ADDRESS: u64 = 0;
const STATUS_PENDING: u64 = 0x0000_0103;
const STATUS_PROCEDURE_NOT_FOUND: u64 = 0xc000_007a;
const STATUS_DLL_NOT_FOUND: u64 = 0xc000_0135;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
/// `MAX_PATH` bounds a delay descriptor's DLL name; an export name is bounded
/// by the same limit Windows imposes on a decorated symbol.
const MAX_DLL_NAME: u64 = 260;
const MAX_IMPORT_NAME: u64 = 1024;

pub(super) fn resolve(args: [u64; 6]) -> u64 {
    let [base, descriptor, dllhook, syshook, thunk, _flags] = args;
    let Some(task) = sched::live::current() else { return NO_ADDRESS; };
    if !task.is_nt_personality() { return NO_ADDRESS; }
    let mut raw = [0u8; policy::DELAY_DESCRIPTOR_BYTES];
    if descriptor == 0 || uaccess::copy_from_user(&mut raw, descriptor).is_err() { return NO_ADDRESS; }
    let parsed = policy::parse_descriptor(&raw);
    let Some(tables) = tables(base, thunk, &parsed) else { return NO_ADDRESS; };
    let Ok(entry) = uaccess::get_user_u64(tables.name_slot) else { return NO_ADDRESS; };
    let selector = policy::import_selector(entry);
    let name_address = match selector {
        ImportSelector::Name { name_rva } => policy::import_name_address(base, name_rva).unwrap_or(0),
        ImportSelector::Ordinal(_) => 0,
    };
    let mut module = uaccess::get_user_u64(tables.module_handle).unwrap_or(0);
    let mut last_error: u64 = 0;
    if module == 0 {
        last_error = match read_ascii_z(tables.dll_name, MAX_DLL_NAME) {
            Some(name) => crate::nt_loader_dir::load_delay_module(&name, tables.module_handle),
            None => STATUS_INVALID_PARAMETER,
        };
        module = uaccess::get_user_u64(tables.module_handle).unwrap_or(0);
        if last_error == 0 && module == 0 { last_error = STATUS_DLL_NOT_FOUND; }
    }
    let import = match selector {
        ImportSelector::Ordinal(_) => None,
        ImportSelector::Name { .. } => match read_ascii_z(name_address, MAX_IMPORT_NAME) { Some(name) => Some(name), None => return NO_ADDRESS },
    };
    let address = if module == 0 || last_error != 0 { None } else {
        match selector {
            ImportSelector::Ordinal(ordinal) => crate::nt_loader_proc::procedure_address(&task, module, None, ordinal),
            ImportSelector::Name { .. } => import.as_deref().and_then(|name| crate::nt_loader_proc::procedure_address(&task, module, Some(name), 0)),
        }
    };
    if let Some(address) = address {
        if uaccess::put_user_u64(tables.slot, address).is_err() { return NO_ADDRESS; }
        return address;
    }
    if last_error == 0 { last_error = STATUS_PROCEDURE_NOT_FOUND; }
    report_failure(tables.dll_name, &import, selector, last_error);
    let info = policy::serialize_delayload_info(descriptor, thunk, tables.dll_name,
        matches!(selector, ImportSelector::Name { .. }), entry as u16 as u64, module, last_error as u32);
    begin_failure_hook(&task, dllhook, syshook, &info, tables.dll_name, selector, name_address)
}

/// Addresses the delay descriptor names for one thunk.
struct Tables { module_handle: u64, dll_name: u64, slot: u64, name_slot: u64 }

fn tables(base: u64, thunk: u64, parsed: &DelayDescriptor) -> Option<Tables> {
    let module_handle = policy::rva_target(base, parsed.module_handle_rva)?;
    let dll_name = policy::rva_target(base, parsed.dll_name_rva)?;
    let addresses = policy::rva_target(base, parsed.iat_rva)?;
    let names = policy::rva_target(base, parsed.int_rva)?;
    let index = policy::thunk_index(thunk, addresses)?;
    let slot = policy::slot_address(addresses, index)?;
    let name_slot = policy::slot_address(names, index)?;
    Some(Tables { module_handle, dll_name, slot, name_slot })
}

/// Redirect the interrupted frame into the failure hook the caller supplied.
/// The hook returns through ntdll's callback continuation, so its result
/// becomes this service's answer exactly as a direct call would.
fn begin_failure_hook(task: &sched::Task, dllhook: u64, syshook: u64, info: &[u8], dll_name: u64,
    selector: ImportSelector, name_address: u64) -> u64 {
    let regs = crate::arch_frame::current_user_regs();
    if regs.is_null() { return NO_ADDRESS; }
    // SAFETY: current_user_regs is the live syscall entry frame this dispatch
    // owns; redirecting it changes only this task's return-to-user path.
    let frame = unsafe { &mut *regs };
    let Some(reserved) = policy::hook_frame(frame.rsp) else { return NO_ADDRESS; };
    let target = policy::failure_target(dllhook, syshook, reserved.info, dll_name, selector, name_address);
    let (entry, first, second) = match target {
        FailureTarget::DllHook { entry, info } => (entry, policy::DELAYLOAD_GPA_FAILURE, info),
        FailureTarget::SystemHook { entry, dll_name, api } => (entry, dll_name, api),
        FailureTarget::None => return NO_ADDRESS,
    };
    if !uaccess::access_ok(entry, 1) { return NO_ADDRESS; }
    let ntdll = crate::nt_loader_proc::module_base_by_name(task, b"ntdll.dll").unwrap_or(0);
    let Some(continuation) = elf_load::pe_loader::resolve_nt_runtime_wndproc_continuation(ntdll) else { return NO_ADDRESS; };
    if matches!(target, FailureTarget::DllHook { .. }) && uaccess::copy_to_user(reserved.info, info).is_err() { return NO_ADDRESS; }
    for slot in 0..4u64 { if uaccess::put_user_u64(reserved.rsp + 8 + slot * 8, 0).is_err() { return NO_ADDRESS; } }
    if uaccess::put_user_u64(reserved.rsp, continuation).is_err() { return NO_ADDRESS; }
    let saved = crate::nt_callback_frame::capture(frame, task, sched::nt_callback::Completion::NONE);
    if !task.nt_callback_stack.lock().push(saved) { return NO_ADDRESS; }
    frame.rip = entry;
    frame.rsp = reserved.rsp;
    frame.rcx = first;
    frame.rdx = second;
    STATUS_PENDING
}

/// Name the import that could not be bound. A delay-load failure ends in a
/// hook that raises, so the unbound symbol has to reach the log first.
#[cfg(feature = "debug-faultdiag")]
fn report_failure(dll_name: u64, import: &Option<Vec<u8>>, selector: ImportSelector, status: u64) {
    klog::write_raw(b"[WINDOWS-DELAYLOAD-FAIL] dll=");
    match read_ascii_z(dll_name, MAX_DLL_NAME) { Some(name) => klog::write_raw(&name), None => klog::write_raw(b"<unreadable>") }
    klog::write_raw(b" api=");
    match (import, selector) {
        (Some(name), _) => klog::write_raw(name),
        (None, ImportSelector::Ordinal(ordinal)) => klog::write_hex_u64(ordinal as u64),
        (None, ImportSelector::Name { .. }) => klog::write_raw(b"<unreadable>"),
    }
    klog::write_raw(b" status=");
    klog::write_hex_u64(status);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-faultdiag"))]
fn report_failure(_dll_name: u64, _import: &Option<Vec<u8>>, _selector: ImportSelector, _status: u64) {}

fn read_ascii_z(address: u64, limit: u64) -> Option<Vec<u8>> {
    if address == 0 { return None; }
    let mut value = Vec::new();
    for offset in 0..limit {
        let mut byte = [0u8; 1];
        if uaccess::copy_from_user(&mut byte, address.checked_add(offset)?).is_err() { return None; }
        if byte[0] == 0 { return (!value.is_empty()).then_some(value); }
        value.push(byte[0]);
    }
    None
}
