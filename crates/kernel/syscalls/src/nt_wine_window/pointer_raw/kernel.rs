//! Kernel binding: read the client records, call the canonical pointer owner
//! and write the answers back.
use crate::nt_window::user_input as owner;
use super::*;

const FALSE: u64 = 0;
const TRUE: u64 = 1;

/// # C: O(1)
fn system_dpi() -> i32 { drm::primary_system_dpi() as i32 }

/// # C: O(N_queues + N_pointers) plus bounded usercopy
fn get_pointer_type(id: u32, out: u64) -> u64 {
    if out == 0 { return FALSE; }
    let Some(kind) = owner::pointer_type_for_current(id) else { return FALSE; };
    uaccess::copy_to_user(out, &kind.to_le_bytes()).is_ok() as u64
}

/// # C: O(N_queues + N_pointers) plus bounded usercopy
fn get_pointer_info_list(args: &[u64]) -> u64 {
    let (id, kind, size) = (args[0] as u32, args[1] as u32, args[4]);
    let (entry_count, pointer_count, info) = (args[5], args[6], args[7]);
    let InfoList::Answer(record) = check_info_list(kind, size, entry_count, pointer_count, info) else { return FALSE; };
    let Some(stored) = owner::pointer_info_for_current(id) else { return FALSE; };
    if uaccess::copy_to_user(entry_count, &ONE_ENTRY.to_le_bytes()).is_err() { return FALSE; }
    if uaccess::copy_to_user(pointer_count, &ONE_ENTRY.to_le_bytes()).is_err() { return FALSE; }
    // The record is cleared to its declared width, then the pointer
    // information is written over its head: every wider record carries the
    // pointer information first and its own fields after.
    let mut cleared = 0usize;
    while cleared < record {
        let chunk = core::cmp::min(record - cleared, ZERO_CHUNK.len());
        let Some(address) = info.checked_add(cleared as u64) else { return FALSE; };
        if uaccess::copy_to_user(address, &ZERO_CHUNK[..chunk]).is_err() { return FALSE; }
        cleared += chunk;
    }
    uaccess::copy_to_user(info, &encode_pointer_info(stored, system_dpi())).is_ok() as u64
}

/// Zero written in bounded steps, so no allocation is needed to clear a record.
const ZERO_CHUNK: [u8; 64] = [0u8; 64];

/// # C: O(N_monitors) plus bounded usercopy
fn get_pointer_device_rects(handle: u64, device: u64, display: u64) -> u64 {
    // No pointer device is present, so only the whole-screen handle is
    // answered; a named device reports that it holds no data.
    if handle != INVALID_HANDLE_VALUE { return FALSE; }
    if device == 0 || display == 0 { return FALSE; }
    let screen = owner::virtual_screen();
    if uaccess::copy_to_user(device, &encode_rect(device_rect(screen, system_dpi()))).is_err() { return FALSE; }
    uaccess::copy_to_user(display, &encode_rect(screen)).is_ok() as u64
}

/// Answer the pointer queries and touch injection. # C: O(owner work)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if !claims(ordinal) { return None; }
    Some(match ordinal {
        GET_POINTER_TYPE if args.len() >= 2 => get_pointer_type(args[0] as u32, args[1]),
        GET_POINTER_INFO_LIST if args.len() >= 8 => get_pointer_info_list(args),
        GET_POINTER_DEVICE_RECTS if args.len() >= 3 => get_pointer_device_rects(args[0], args[1], args[2]),
        // Touch injection needs no device to be initialized: the injected
        // contacts are synthesised, and the first injection is what would need
        // one.
        INITIALIZE_TOUCH_INJECTION if args.len() >= 2 => TRUE,
        _ => return None,
    })
}
