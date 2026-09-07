//! Kernel binding: enumerate the desktop input devices and keep the calling
//! process's usage registrations.
use alloc::vec::Vec;
use crate::nt_window::user_input as owner;
use super::*;

const FALSE: u64 = 0;


/// # C: O(N_devices)
fn device_list(args: &[u64]) -> u64 {
    let (buffer, count, size) = (args[0], args[1], args[2] as u32);
    if size as usize != RAWINPUTDEVICELIST_BYTES { return REFUSED; }
    if count == 0 { return REFUSED; }
    let Ok(capacity) = uaccess::get_user_u32(count) else { return REFUSED; };
    let list = devices();
    let (written, fits) = listing_plan(buffer, capacity, list.len());
    for (index, device) in list.iter().take(written).enumerate() {
        let Some(address) = buffer.checked_add((index * RAWINPUTDEVICELIST_BYTES) as u64) else { return REFUSED; };
        if uaccess::copy_to_user(address, &encode_device(*device)).is_err() { return REFUSED; }
    }
    if buffer == 0 {
        if uaccess::put_user_u32(count, list.len() as u32).is_err() { return REFUSED; }
        return 0;
    }
    if !fits {
        let _ = uaccess::put_user_u32(count, list.len() as u32);
        return REFUSED;
    }
    written as u64
}

/// # C: O(N_devices)
fn device_info_query(args: &[u64]) -> u64 {
    let (handle, command, data, size) = (args[0], args[1] as u32, args[2], args[3]);
    if size == 0 { return REFUSED; }
    let Some(length) = device_info_length(command, handle) else { return REFUSED; };
    let Ok(capacity) = uaccess::get_user_u32(size) else { return REFUSED; };
    if data != 0 && capacity >= length {
        match command {
            RIDI_DEVICENAME => {
                let Some(path) = device_path(handle) else { return REFUSED; };
                for (index, unit) in path.iter().enumerate() {
                    let Some(address) = data.checked_add((index * 2) as u64) else { return REFUSED; };
                    if uaccess::copy_to_user(address, &unit.to_le_bytes()).is_err() { return REFUSED; }
                }
                let Some(terminator) = data.checked_add((path.len() * 2) as u64) else { return REFUSED; };
                if uaccess::copy_to_user(terminator, &[0, 0]).is_err() { return REFUSED; }
            }
            RIDI_DEVICEINFO => {
                let Some(info) = device_info(handle) else { return REFUSED; };
                if uaccess::copy_to_user(data, &info).is_err() { return REFUSED; }
            }
            _ => {}
        }
    }
    if uaccess::put_user_u32(size, length).is_err() { return REFUSED; }
    if data == 0 { return 0; }
    if capacity < length { return REFUSED; }
    length as u64
}

/// # C: O(N_registrations)
fn registered_devices(args: &[u64]) -> u64 {
    let (buffer, count, size) = (args[0], args[1], args[2] as u32);
    if size as usize != RAWINPUTDEVICE_BYTES || count == 0 { return REFUSED; }
    let Ok(capacity) = uaccess::get_user_u32(count) else { return REFUSED; };
    if buffer != 0 && capacity == 0 { return REFUSED; }
    let list = owner::registered_raw_input_for_current();
    if uaccess::put_user_u32(count, list.len() as u32).is_err() { return REFUSED; }
    if buffer == 0 { return 0; }
    if (capacity as usize) < list.len() { return REFUSED; }
    for (index, entry) in list.iter().enumerate() {
        let Some(address) = buffer.checked_add((index * RAWINPUTDEVICE_BYTES) as u64) else { return REFUSED; };
        if uaccess::copy_to_user(address, &encode_registration(*entry)).is_err() { return REFUSED; }
    }
    list.len() as u64
}

/// # C: O(N_batch)
fn register_devices(args: &[u64]) -> u64 {
    let (devices, count, size) = (args[0], args[1] as u32, args[2] as u32);
    if size as usize != RAWINPUTDEVICE_BYTES { return FALSE; }
    if count as usize > MAX_BATCH { return FALSE; }
    let mut batch: Vec<RawRegistration> = Vec::new();
    if batch.try_reserve_exact(count as usize).is_err() { return FALSE; }
    for index in 0..count as u64 {
        let Some(address) = devices.checked_add(index * RAWINPUTDEVICE_BYTES as u64) else { return FALSE; };
        let mut bytes = [0u8; RAWINPUTDEVICE_BYTES];
        if uaccess::copy_from_user(&mut bytes, address).is_err() { return FALSE; }
        batch.push(decode_registration(&bytes));
    }
    owner::register_raw_input_for_current(&batch).is_ok() as u64
}

/// Answer the raw-input ordinals. # C: O(owner work)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    Some(match ordinal {
        GET_RAW_INPUT_DEVICE_LIST if args.len() >= 3 => device_list(args),
        GET_RAW_INPUT_DEVICE_INFO if args.len() >= 4 => device_info_query(args),
        GET_REGISTERED_RAW_INPUT_DEVICES if args.len() >= 3 => registered_devices(args),
        REGISTER_RAW_INPUT_DEVICES if args.len() >= 3 => register_devices(args),
        // No raw record is retained for a message until raw input is delivered
        // to a queue; the reference answers the same when the calling thread
        // holds none.
        GET_RAW_INPUT_DATA if args.len() >= 5 => REFUSED,
        GET_RAW_INPUT_BUFFER if args.len() >= 3 => {
            if args[2] as usize != RAWINPUTHEADER_BYTES || args[1] == 0 { return Some(REFUSED); }
            if uaccess::put_user_u32(args[1], 0).is_err() { return Some(REFUSED); }
            0
        }
        _ => return None,
    })
}

