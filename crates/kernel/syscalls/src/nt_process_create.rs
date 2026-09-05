//! x86-64 native process creation: validate the user ABI, prepare a PE image,
//! then publish one fully initialized task and its process/thread objects.
#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

use alloc::{string::String, sync::Arc, vec, vec::Vec};
use core::sync::atomic::Ordering;
use syscall::nt::NtCall;

const SUCCESS: u64 = 0;
const INVALID_PARAMETER: u64 = 0xc000_000d;
const NO_MEMORY: u64 = 0xc000_0017;
const NOT_FOUND: u64 = 0xc000_000f;
const CREATE_SUSPENDED: u32 = 1;
const PS_CREATE_INFO_SIZE: u64 = 88;
const PS_CREATE_SUCCESS: u64 = 6;
const IMAGE_NAME: u64 = 0x0002_0005;
const CLIENT_ID: u64 = 0x0001_0003;
const MAX_ATTRIBUTES: u64 = 64;
const PARAM_CURRENT_DIRECTORY_OFF: u64 = 0x38;
const PARAM_CURRENT_DIRECTORY_HANDLE_OFF: u64 = 0x48;
const PARAM_COMMAND_LINE_OFF: u64 = 0x70;
const PARAM_ENVIRONMENT_OFF: u64 = 0x80;

/// Dispatch the real child-image transaction.  Only the x86-64 native path
/// is exposed: this kernel deliberately does not promise a 32-bit Windows ABI.
pub fn dispatch(call: NtCall, stack: [u64; 5]) -> u64 {
    let Ok(c) = syscall::nt::decode_user_process(call, stack) else { return INVALID_PARAMETER; };
    let Some(cur) = sched::live::current() else { return INVALID_PARAMETER; };
    if !cur.is_nt_personality()
        || !crate::nt_process_policy::valid_process_create_flags(c.process_flags as u32)
        || c.thread_flags & !CREATE_SUSPENDED != 0
        || !crate::nt_process_handles::valid_object_attributes(c.process_attributes)
        || !crate::nt_process_handles::valid_object_attributes(c.thread_attributes)
        || read_u64(c.create_info.as_u64()) != Some(PS_CREATE_INFO_SIZE) {
        return INVALID_PARAMETER;
    }
    let Some(image) = image_path(c.attribute_list) else { return INVALID_PARAMETER; };
    let Ok(image_path) = String::from_utf8(image.clone()) else { return INVALID_PARAMETER; };
    let Some((command, environment, current_directory, current_directory_handle, console_handle, standard_handles)) =
        process_parameters(c.process_parameters) else { return INVALID_PARAMETER; };
    let environment_refs: Vec<(&str, &str)> = environment.iter().map(|(name, value)|
        (name.as_str(), value.as_str())).collect();
    let params = elf_load::process_env::NtProcessParameters {
        current_directory: current_directory.as_str(), current_directory_handle,
        console_handle, standard_handles,
    };
    let Ok((blob, vp)) = crate::execve_common::open_exec_image(&image) else { return NOT_FOUND; };
    let tid = sched::live::next_tid();
    let catalog = cur.thread_group.nt_module_catalog();
    let Ok(prepared) = crate::pe_exec::prepare_pe_process(&cur, &image, &blob,
        Some(command.as_str()), &environment_refs, Some(&params), vp.as_ref(), catalog.as_deref(), tid, tid, false) else { return INVALID_PARAMETER; };
    let Ok(continuation) = crate::pe_exec::PeLaunchContinuation::new(prepared) else { return INVALID_PARAMETER; };
    let prepared = continuation.prepared();

    // Everything above is private and fallible.  From here the task is built
    // unpublished, so a caller cannot observe an image without its PEB/TEB.
    let child = match unsafe { sched::live::new_user_task_unpublished(tid, 0, 0,
        "nt-process", Arc::clone(&prepared.mm)) } {
        Ok(task) => task,
        Err(_) => return NO_MEMORY,
    };
    if child.alloc_pid_mappings(&[], true).is_err() { return NO_MEMORY; }
    child.parent_tid.store(cur.tid, Ordering::Release);
    child.exit_signal.store(sched::signum::Signum::Sigchld as u8, Ordering::Release);
    child.inherit_fs_context_from(&cur, false);
    child.set_pgrp(cur.pgrp());
    child.set_session(cur.session());
    child.inherit_audit_identity(&cur);
    child.set_nt_personality(true);
    sched::initialize_new_thread(&child);
    child.set_nt_peb(prepared.process.environment.peb.as_u64());
    child.set_nt_teb(prepared.process.environment.teb.as_u64());
    child.set_exe_path(Some(image_path.clone()));
    // SAFETY: the unpublished child owns the freshly prepared address space;
    // no other task can observe or replace this mm before publication below.
    if let Some(mm) = unsafe { child.mm_ref() } { mm.set_exe_path(image_path.clone()); }
    if let Some(catalog) = catalog { child.thread_group.set_nt_module_catalog(catalog); }
    if crate::nt_process_policy::inherits_process_handles(c.process_flags as u32) {
        if let Some(fd) = cur.clone_fd_table() {
            // A new NT process owns an independent descriptor snapshot. A
            // shared Arc would make parent-side close/exec mutations visible
            // in the child, unlike Linux fork's copied files_struct.
            unsafe { child.replace_fd_table(Some(Arc::new(fd.fork_clone()))); }
        }
    }
    let startup = continuation.startup();
    unsafe { sched::live::arm_user_entry(&child, startup.transfer_entry.as_u64(),
        startup.stack_pointer.as_u64()); }
    // The NT TEB is addressed through GS on x86-64.  `arm_user_entry` builds
    // a generic user context, so the native process transaction must publish
    // the image-specific GS base before the task becomes visible to the
    // scheduler; otherwise the first instruction in ntdll/user32 observes a
    // zero TEB even though the task metadata points at the right one.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let ctx = child.arch_ctx_ptr::<hal_x86_64::ContextX86_64>();
        (*ctx).gs_base = startup.gs_base.as_u64();
    }

    let table = cur.thread_group.nt_handles();
    let process = table.insert(table.new_process(Arc::clone(&child)),
        c.process_access | crate::nt_process_handles::SYNCHRONIZE);
    let Some(process) = process else { return NO_MEMORY; };
    let thread = table.insert(table.new_thread(Arc::clone(&child)),
        c.thread_access | crate::nt_process_handles::SYNCHRONIZE);
    let Some(thread) = thread else { let _ = table.close(process); return NO_MEMORY; };
    if uaccess::put_user_u32(c.process_handle.as_u64(), process.raw()).is_err()
        || uaccess::put_user_u32(c.thread_handle.as_u64(), thread.raw()).is_err() {
        let _ = table.close(thread); let _ = table.close(process); return INVALID_PARAMETER;
    }
    // PS_CREATE_INFO.SuccessState is the canonical handoff from the kernel
    // process transaction to Wine's RtlCreateUserProcess caller. Keep every
    // field inside the caller-declared 88-byte x64 record initialized; a
    // state-only write leaves stale parameter pointers visible on reuse.
    if !write_create_success(c.create_info.as_u64(), &prepared.process.environment) {
        let _ = table.close(thread); let _ = table.close(process); return INVALID_PARAMETER;
    }
    if let Some(client) = client_id(c.attribute_list) {
        if uaccess::put_user_u64(client, child.tgid.load(Ordering::Acquire) as u64).is_err()
            || uaccess::put_user_u64(client + 8, child.tid as u64).is_err() {
            let _ = table.close(thread);
            let _ = table.close(process);
            return INVALID_PARAMETER;
        }
    }
    let _ = continuation.take();
    sched::live::publish_new_task(&child);
    if crate::nt_process_policy::initial_thread_suspended(c.process_flags as u32, c.thread_flags as u32) { let _ = child.nt_suspend(); }
    else { sched::live::wake_new_task(&child); }
    SUCCESS
}

fn write_create_success(address: u64, environment: &elf_load::process_env::NtProcessEnvironment) -> bool {
    uaccess::put_user_u64(address + 8, PS_CREATE_SUCCESS).is_ok()
        && uaccess::put_user_u32(address + 16, 0).is_ok()
        && uaccess::put_user_u64(address + 24, 0).is_ok()
        && uaccess::put_user_u64(address + 32, 0).is_ok()
        && uaccess::put_user_u64(address + 40, environment.process_parameters.as_u64()).is_ok()
        && uaccess::put_user_u32(address + 48, 0).is_ok()
        && uaccess::put_user_u32(address + 52, 1).is_ok()
        && uaccess::put_user_u64(address + 56, environment.peb.as_u64()).is_ok()
        && uaccess::put_user_u64(address + 64, 0).is_ok()
        && uaccess::put_user_u32(address + 72, 0).is_ok()
}

fn read_u16(address: u64) -> Option<u16> {
    let mut bytes = [0u8; 2];
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u64(address: u64) -> Option<u64> { uaccess::get_user_u64(address).ok() }

/// Copy the normalized RTL process parameters before creating the child.
/// The returned strings own their storage so no parent address-space pointer
/// survives the transaction.
fn process_parameters(params: syscall::UserPtr<u8>) -> Option<(String, Vec<(String, String)>, String, u64, u64, [u64; 3])> {
    let command = unicode_field(params.as_u64(), PARAM_COMMAND_LINE_OFF)?;
    let environment = read_environment(read_u64(params.as_u64() + PARAM_ENVIRONMENT_OFF)?)?;
    let current_directory = unicode_field(params.as_u64(), PARAM_CURRENT_DIRECTORY_OFF)?;
    let current_directory_handle = read_u64(params.as_u64() + PARAM_CURRENT_DIRECTORY_HANDLE_OFF)?;
    let console_handle = read_u64(params.as_u64() + 0x10)?;
    let standard_handles = [read_u64(params.as_u64() + 0x20)?,
        read_u64(params.as_u64() + 0x28)?, read_u64(params.as_u64() + 0x30)?];
    Some((command, environment, current_directory, current_directory_handle,
        console_handle, standard_handles))
}

fn unicode_field(base: u64, offset: u64) -> Option<String> {
    let length = read_u16(base.checked_add(offset)?)? as usize;
    let buffer = read_u64(base.checked_add(offset + 8)?)?;
    if length == 0 || length > 32 * 1024 || length & 1 != 0 || buffer == 0 { return None; }
    let mut bytes = vec![0u8; length];
    uaccess::copy_from_user(&mut bytes, buffer).ok()?;
    let units: Vec<u16> = bytes.chunks_exact(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
    crate::nt_process_parameters::decode_utf16(&units)
}

fn read_environment(pointer: u64) -> Option<Vec<(String, String)>> {
    if pointer == 0 { return Some(Vec::new()); }
    const MAX_ENVIRONMENT_BYTES: usize = 1024 * 1024;
    let mut units = Vec::new();
    let mut previous_zero = false;
    for index in 0..(MAX_ENVIRONMENT_BYTES / 2) {
        let address = pointer.checked_add((index * 2) as u64)?;
        let mut bytes = [0u8; 2];
        uaccess::copy_from_user(&mut bytes, address).ok()?;
        let unit = u16::from_le_bytes(bytes);
        units.push(unit);
        if unit == 0 {
            if previous_zero { return crate::nt_process_parameters::parse_environment(&units); }
            previous_zero = true;
        } else { previous_zero = false; }
    }
    None
}

fn image_path(list: syscall::UserPtr<u8>) -> Option<Vec<u8>> {
    let (image, size, _) = attributes(list)?;
    if size == 0 || size > 4094 || size & 1 != 0 { return None; }
    let mut raw = vec![0u8; size as usize];
    uaccess::copy_from_user(&mut raw, image).ok()?;
    let units = raw.chunks_exact(2).map(|p| u16::from_le_bytes([p[0], p[1]]));
    let mut out = String::new();
    for unit in units {
        if unit > 0x7f { return None; }
        out.push(unit as u8 as char);
    }
    let mut path = out.strip_prefix("\\??\\").unwrap_or(&out).replace('\\', "/");
    if path.starts_with("Z:/") {
        // Wine's default Z: drive is the host root. Other drive mappings are
        // intentionally left to the future per-process DOS-device map.
        path.replace_range(..2, "");
    }
    Some(path.into_bytes())
}

fn client_id(list: syscall::UserPtr<u8>) -> Option<u64> { attributes(list).and_then(|(_, _, c)| c) }

fn attributes(list: syscall::UserPtr<u8>) -> Option<(u64, u64, Option<u64>)> {
    let total = uaccess::get_user_u64(list.as_u64()).ok()?;
    if total < 40 || total > 8 + MAX_ATTRIBUTES * 32 || total & 7 != 0 { return None; }
    let mut image = None;
    let mut image_size = 0;
    let mut client = None;
    let count = (total - 8) / 32;
    for i in 0..count {
        let p = list.as_u64().checked_add(8 + i * 32)?;
        let attr = uaccess::get_user_u64(p).ok()?;
        let size = uaccess::get_user_u64(p + 8).ok()?;
        let value = uaccess::get_user_u64(p + 16).ok()?;
        if attr == IMAGE_NAME { image = Some(value); image_size = size; }
        if attr == CLIENT_ID && size >= 16 { client = Some(value); }
    }
    Some((image?, image_size, client))
}
