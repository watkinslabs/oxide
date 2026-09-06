//! Kernel binding: user copies, key state and synchronous sends for the accelerator syscalls.
use super::*;
use ipc::win32_accel;

const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;

fn create(table: u64, count: u64) -> u64 {
    let count = count as i32 as i64;
    if table == 0 || !(1..=MAX_TABLE_ENTRIES as i64).contains(&count) { return 0; }
    let mut bytes = alloc::vec![0u8; count as usize * ACCEL_BYTES];
    if uaccess::copy_from_user(&mut bytes, table).is_err() { return 0; }
    let Some(entries) = decode_table(&bytes, count) else { return 0; };
    crate::nt_window::accel_create_for_current(&entries).map(u64::from).unwrap_or(0)
}

fn copy(handle: u64, destination: u64, count: u64) -> u64 {
    let Ok(handle) = u32::try_from(handle) else { return 0; };
    let limit = if destination == 0 { usize::MAX } else { usize::try_from(count as i32).unwrap_or(0) };
    let Ok(entries) = crate::nt_window::accel_copy_for_current(handle, limit) else { return 0; };
    if destination == 0 { return entries.len() as u64; }
    let mut bytes = alloc::vec::Vec::with_capacity(entries.len() * ACCEL_BYTES);
    for entry in &entries { bytes.extend_from_slice(&entry.encode()); }
    if uaccess::copy_to_user(destination, &bytes).is_err() { return 0; }
    entries.len() as u64
}

fn destroy(handle: u64) -> u64 {
    let Ok(handle) = u32::try_from(handle) else { return 0; };
    u64::from(crate::nt_window::accel_destroy_for_current(handle).is_ok())
}

fn translate(hwnd: u64, handle: u64, pointer: u64) -> u64 {
    if hwnd == 0 || pointer == 0 { return 0; }
    let mut bytes = [0u8; MSG_PREFIX_BYTES];
    if uaccess::copy_from_user(&mut bytes, pointer).is_err() { return STATUS_ACCESS_VIOLATION; }
    let msg = Msg::decode(&bytes).unwrap();
    if !win32_accel::is_accelerator_message(msg.message) { return 0; }
    let Ok(handle) = u32::try_from(handle) else { return 0; };
    let Ok(entries) = crate::nt_window::accel_copy_for_current(handle, usize::MAX) else { return 0; };
    let mask = modifiers(|key| crate::nt_window::get_key_state_current(u64::from(key)));
    let Some(hit) = win32_accel::find(msg.message, msg.wparam, msg.lparam, mask, &entries) else { return 0; };
    let Some(target) = crate::nt_window::accel_target_for_current(hwnd, hit.cmd) else { return 0; };
    for (message, wparam, lparam) in plan(hit.cmd, target) {
        crate::nt_window::send::send_for_current(hwnd, message, wparam, lparam);
    }
    1
}

/// # C: O(entries) plus bounded usercopy; # Sleeps: yes (synchronous sends)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    let [a0, a1, a2, ..] = args else { return None; };
    Some(match ordinal {
        CREATE_TABLE => create(*a0, *a1),
        COPY_TABLE => copy(*a0, *a1, *a2),
        DESTROY_TABLE => destroy(*a0),
        TRANSLATE => translate(*a0, *a1, *a2),
        _ => return None,
    })
}
