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
const IMAGE_NAME: u64 = 0x0002_0005;
const CLIENT_ID: u64 = 0x0001_0003;
const MAX_ATTRIBUTES: u64 = 64;

/// Dispatch the real child-image transaction.  Only the x86-64 native path
/// is exposed: this kernel deliberately does not promise a 32-bit Windows ABI.
pub fn dispatch(call: NtCall, stack: [u64; 5]) -> u64 {
    let Ok(c) = syscall::nt::decode_user_process(call, stack) else { return INVALID_PARAMETER; };
    let Some(cur) = sched::live::current() else { return INVALID_PARAMETER; };
    if !cur.is_nt_personality() || c.process_flags != 0 || c.thread_flags & !CREATE_SUSPENDED != 0
        || !crate::nt_process_handles::valid_object_attributes(c.process_attributes)
        || !crate::nt_process_handles::valid_object_attributes(c.thread_attributes) {
        return INVALID_PARAMETER;
    }
    let Some(image) = image_path(c.attribute_list) else { return INVALID_PARAMETER; };
    let Ok((blob, vp)) = crate::execve_common::open_exec_image(&image) else { return NOT_FOUND; };
    let tid = sched::live::next_tid();
    let catalog = cur.thread_group.nt_module_catalog();
    let Ok(prepared) = crate::pe_exec::prepare_pe_process(&cur, &image, &blob, vp.as_ref(),
        catalog.as_deref(), tid, tid, false) else { return INVALID_PARAMETER; };

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
    child.set_nt_peb(prepared.process.environment.peb.as_u64());
    child.set_nt_teb(prepared.process.environment.teb.as_u64());
    if let Some(catalog) = catalog { child.thread_group.set_nt_module_catalog(catalog); }
    if let Some(fd) = cur.clone_fd_table() {
        unsafe { child.replace_fd_table(Some(fd)); }
    }
    unsafe { sched::live::arm_user_entry(&child, prepared.process.entry.rip.as_u64(),
        prepared.process.entry.rsp.as_u64()); }

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
    // PS_CREATE_INFO.State == PsCreateSuccess; PEB is the first useful
    // success-state field to Wine's RtlCreateUserProcess callers.
    if uaccess::put_user_u64(c.create_info.as_u64() + 8, 6).is_err()
        || uaccess::put_user_u64(c.create_info.as_u64() + 56,
            prepared.process.environment.peb.as_u64()).is_err() {
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
    sched::live::publish_new_task(&child);
    if c.thread_flags & CREATE_SUSPENDED != 0 { child.nt_suspend(); }
    else { sched::live::wake_new_task(&child); }
    SUCCESS
}

fn read_u16(address: u64) -> Option<u16> { uaccess::get_user_u32(address).ok().map(|v| v as u16) }

fn image_path(list: syscall::UserPtr<u8>) -> Option<Vec<u8>> {
    let (image, _) = attributes(list)?;
    let len = read_u16(image)? as u64;
    let buffer = uaccess::get_user_u64(image + 8).ok()?;
    if len == 0 || len > 4094 || buffer == 0 || len & 1 != 0 { return None; }
    let mut raw = vec![0u8; len as usize];
    uaccess::copy_from_user(&mut raw, buffer).ok()?;
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

fn client_id(list: syscall::UserPtr<u8>) -> Option<u64> { attributes(list).and_then(|(_, c)| c) }

fn attributes(list: syscall::UserPtr<u8>) -> Option<(u64, Option<u64>)> {
    let total = uaccess::get_user_u64(list.as_u64()).ok()?;
    if total < 40 || total > 8 + MAX_ATTRIBUTES * 32 || total & 7 != 0 { return None; }
    let mut image = None;
    let mut client = None;
    let count = (total - 8) / 32;
    for i in 0..count {
        let p = list.as_u64().checked_add(8 + i * 32)?;
        let attr = uaccess::get_user_u64(p).ok()?;
        let size = uaccess::get_user_u64(p + 8).ok()?;
        let value = uaccess::get_user_u64(p + 16).ok()?;
        if attr == IMAGE_NAME && size >= 8 { image = Some(value); }
        if attr == CLIENT_ID && size >= 16 { client = Some(value); }
    }
    Some((image?, client))
}
