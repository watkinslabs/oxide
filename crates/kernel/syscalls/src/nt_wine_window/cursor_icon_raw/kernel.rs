//! Kernel binding: read the client records, call the canonical cursor/icon
//! owner, and write the answers back.
use alloc::vec::Vec;
use ipc::win32_window::{CursorFrame, CursorIconDesc, ICON_BIG, ICON_SMALL};
use crate::nt_window::user_input as owner;
use super::*;

const FALSE: u64 = 0;
const TRUE: u64 = 1;

/// # C: O(1)
fn read_u32(address: u64) -> Option<u32> { uaccess::get_user_u32(address).ok() }

/// Read one `UNICODE_STRING`, answering its units and, when the buffer is an
/// integer resource, that identifier instead. # C: O(N_units)
fn read_string(pointer: u64) -> Option<(Vec<u16>, Option<u16>)> {
    if pointer == 0 { return Some((Vec::new(), None)); }
    let length = uaccess::get_user_u16(pointer.checked_add(STRING_LENGTH)?).ok()? as usize;
    let buffer = uaccess::get_user_u64(pointer.checked_add(STRING_BUFFER)?).ok()?;
    if length == 0 { return Some((Vec::new(), integer_resource(buffer))); }
    if length & 1 != 0 || length / 2 > MAX_RESOURCE_NAME { return None; }
    let mut units = Vec::new();
    units.try_reserve_exact(length / 2).ok()?;
    for index in 0..length / 2 {
        units.push(uaccess::get_user_u16(buffer.checked_add((index * 2) as u64)?).ok()?);
    }
    Some((units, None))
}

/// # C: O(1)
fn read_frame(base: u64) -> Option<CursorFrame> {
    Some(CursorFrame {
        width: read_u32(base.checked_add(FRAME_WIDTH)?)? as i32,
        height: read_u32(base.checked_add(FRAME_HEIGHT)?)? as i32,
        color: uaccess::get_user_u64(base.checked_add(FRAME_COLOR)?).ok()?,
        alpha: uaccess::get_user_u64(base.checked_add(FRAME_ALPHA)?).ok()?,
        mask: uaccess::get_user_u64(base.checked_add(FRAME_MASK)?).ok()?,
        hotspot_x: read_u32(base.checked_add(FRAME_HOTSPOT_X)?)? as i32,
        hotspot_y: read_u32(base.checked_add(FRAME_HOTSPOT_Y)?)? as i32,
    })
}

/// # C: O(N_words)
fn read_words(pointer: u64, count: usize) -> Option<Vec<u32>> {
    if pointer == 0 { return Some(Vec::new()); }
    let mut words = Vec::new();
    words.try_reserve_exact(count).ok()?;
    for index in 0..count { words.push(read_u32(pointer.checked_add((index * 4) as u64)?)?); }
    Some(words)
}

/// Fill one cursor or icon object from its client description.
/// # C: O(N_frames + N_steps)
fn set_cursor_icon_data(args: &[u64]) -> u64 {
    let (handle, module, res_name, desc) = (args[0], args[1], args[2], args[3]);
    if handle == 0 || desc == 0 { return FALSE; }
    let Some(flags) = read_u32(desc + DESC_FLAGS) else { return FALSE; };
    let Some(num_steps) = read_u32(desc + DESC_NUM_STEPS) else { return FALSE; };
    let Some(num_frames) = read_u32(desc + DESC_NUM_FRAMES) else { return FALSE; };
    let Some(delay) = read_u32(desc + DESC_DELAY) else { return FALSE; };
    let Ok(frames_ptr) = uaccess::get_user_u64(desc + DESC_FRAMES) else { return FALSE; };
    let Ok(seq_ptr) = uaccess::get_user_u64(desc + DESC_FRAME_SEQ) else { return FALSE; };
    let Ok(rates_ptr) = uaccess::get_user_u64(desc + DESC_FRAME_RATES) else { return FALSE; };
    let Ok(rsrc) = uaccess::get_user_u64(desc + DESC_RSRC) else { return FALSE; };
    let count = if num_steps == 0 { 1 } else { num_frames as usize };
    if frames_ptr == 0 || count == 0 || count > MAX_FRAMES { return FALSE; }
    let mut frames = Vec::new();
    if frames.try_reserve_exact(count).is_err() { return FALSE; }
    for index in 0..count {
        let Some(frame) = read_frame(frames_ptr + index as u64 * FRAME_BYTES) else { return FALSE; };
        frames.push(frame);
    }
    let steps = num_steps as usize;
    let Some(frame_seq) = read_words(seq_ptr, steps) else { return FALSE; };
    let Some(frame_rates) = read_words(rates_ptr, steps) else { return FALSE; };
    let Some((module_name, _)) = read_string(module) else { return FALSE; };
    let Some((resource, res_id)) = read_string(res_name) else { return FALSE; };
    let named = (res_name != 0 && !resource.is_empty()).then_some(resource.as_slice());
    let description = CursorIconDesc { delay, num_steps, num_frames, frames: &frames,
        frame_seq: &frame_seq, frame_rates: &frame_rates, flags, rsrc };
    owner::set_cursor_icon_data_for_current(handle, &module_name, named, res_id, &description) as u64
}

/// # C: O(N_cursor_objects)
fn get_icon_info(args: &[u64]) -> u64 {
    let (icon, info, module, res_name) = (args[0], args[1], args[2], args[3]);
    if info == 0 { return FALSE; }
    let Some(mut record) = owner::icon_info_for_current(icon) else { return FALSE; };
    // The caller owns and deletes the bitmaps a query answers, so hand back
    // copies rather than the object's own.
    let Some(mask) = copy_bitmap(record.mask) else { return FALSE; };
    let Some(color) = copy_bitmap(record.color) else { return FALSE; };
    record.mask = mask; record.color = color;
    if uaccess::copy_to_user(info, &encode_icon_info(record)).is_err() { return FALSE; }
    let Some((module_name, resource, res_id)) = owner::icon_resource_for_current(icon) else { return FALSE; };
    if write_string(module, &module_name).is_none() { return FALSE; }
    match res_id {
        Some(id) if resource.is_empty() => { if write_integer_resource(res_name, id).is_none() { return FALSE; } }
        _ => { if write_string(res_name, &resource).is_none() { return FALSE; } }
    }
    if args[4] != 0 && uaccess::put_user_u32(args[4], 0).is_err() { return FALSE; }
    TRUE
}

/// Duplicate one bitmap handle for the caller. A zero handle stays zero.
/// # C: O(bitmap bytes)
fn copy_bitmap(handle: u64) -> Option<u64> {
    if handle == 0 { return Some(0); }
    let source = u32::try_from(handle).ok()?;
    crate::nt_gdi::copy_bitmap_for_current(source).ok().map(u64::from)
}

/// Copy one name into a client `UNICODE_STRING`, clamped to its capacity. The
/// stored length counts characters, not bytes. # C: O(N_units)
fn write_string(pointer: u64, units: &[u16]) -> Option<()> {
    if pointer == 0 { return Some(()); }
    let maximum = uaccess::get_user_u16(pointer.checked_add(STRING_MAXIMUM)?).ok()? as usize;
    let buffer = uaccess::get_user_u64(pointer.checked_add(STRING_BUFFER)?).ok()?;
    let copied = if buffer == 0 { 0 } else { units.len().min(maximum / 2) };
    for (index, unit) in units.iter().take(copied).enumerate() {
        uaccess::copy_to_user(buffer.checked_add((index * 2) as u64)?, &unit.to_le_bytes()).ok()?;
    }
    uaccess::copy_to_user(pointer, &(copied as u16).to_le_bytes()).ok()?;
    Some(())
}

/// An integer resource is reported by its identifier in the buffer field with
/// a zero length. # C: O(1)
fn write_integer_resource(pointer: u64, id: u16) -> Option<()> {
    if pointer == 0 { return Some(()); }
    uaccess::put_user_u64(pointer.checked_add(STRING_BUFFER)?, id as u64).ok()?;
    uaccess::copy_to_user(pointer, &0u16.to_le_bytes()).ok()?;
    Some(())
}

/// # C: O(N_cursor_objects)
fn get_cursor_frame_info(args: &[u64]) -> u64 {
    let (cursor, step, rate, steps) = (args[0], args[1] as u32, args[2], args[3]);
    if rate == 0 || steps == 0 { return 0; }
    let Some(info) = owner::cursor_frame_info_for_current(cursor, step) else { return 0; };
    if uaccess::put_user_u32(rate, info.rate_jiffies).is_err() { return 0; }
    if uaccess::put_user_u32(steps, info.num_steps).is_err() { return 0; }
    info.cursor
}

/// Answer the cursor and icon object ordinals. # C: O(owner work)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    Some(match ordinal {
        SHOW_CURSOR => owner::show_cursor_for_current(*args.first()? != 0).unwrap_or(0) as i64 as u64,
        DESTROY_CURSOR => owner::destroy_cursor_for_current(*args.first()?) as u64,
        SET_CURSOR_ICON_DATA if args.len() >= 4 => set_cursor_icon_data(args),
        FIND_EXISTING_CURSOR_ICON if args.len() >= 3 => {
            let Some((module, _)) = read_string(args[0]) else { return Some(0); };
            owner::find_existing_cursor_icon_for_current(&module, args[2])
        }
        GET_ICON_INFO if args.len() >= 5 => get_icon_info(args),
        GET_ICON_SIZE if args.len() >= 4 => {
            let Some((width, height)) = owner::icon_size_for_current(args[0], args[1] as u32) else { return Some(FALSE); };
            if args[2] == 0 || args[3] == 0 { return Some(FALSE); }
            if uaccess::put_user_u32(args[2], width as u32).is_err() { return Some(FALSE); }
            if uaccess::put_user_u32(args[3], height as u32).is_err() { return Some(FALSE); }
            TRUE
        }
        GET_CURSOR_FRAME_INFO if args.len() >= 4 => get_cursor_frame_info(args),
        INTERNAL_GET_WINDOW_ICON if args.len() >= 2 => {
            let kind = if args[1] == ICON_BIG { ICON_BIG } else { ICON_SMALL };
            owner::window_icon_for_current(args[0], kind).unwrap_or(0)
        }
        _ => return None,
    })
}
