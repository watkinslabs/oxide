//! Kernel binding: the canonical owner answers, then results reach user memory.
use super::{Call, MAX_ARGUMENTS, argument_count, failure};
use crate::nt_gdi::dc_state::{publish_new, retire, with_state};
use ipc::win32_gdi::{DcKind, Rect, GDI_ERROR};

/// Four little-endian LONG fields.
const RECT_BYTES: usize = 16;
/// One little-endian single-precision float.
const FLOAT_BYTES: usize = 4;

/// # C: canonical owner operation plus bounded usercopy
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    let count = argument_count(ordinal)?;
    let Some(full) = crate::nt_wine_window::raw_gather::gather(args, count) else { return Some(failure(ordinal)); };
    super::route(ordinal, &full[..count.min(MAX_ARGUMENTS)], |call| execute(ordinal, call))
}

fn execute(ordinal: u64, call: Call) -> u64 {
    match call {
        Call::Constant(value) => value,
        Call::SaveDc { dc } => u64::from(with_state(|state| state.save_dc(dc)).unwrap_or(0)),
        Call::RestoreDc { dc, level } => u64::from(with_state(|state| state.restore_dc(dc, level)).is_ok()),
        Call::ResetDc { dc } => u64::from(with_state(|state| state.reset_device_mode(dc)).unwrap_or(false)),
        Call::SetLayout { dc, layout } => match with_state(|state| state.set_layout(dc, layout)) {
            Ok(previous) => u64::from(previous), Err(_) => u64::from(GDI_ERROR) },
        Call::GetBoundsRect { dc, rect, flags } => {
            match with_state(|state| state.get_bounds_rect(dc, rect != 0, flags)) {
                Err(_) => 0,
                Ok((result, value)) => match value {
                    Some(value) if !write_rect(rect, value) => 0,
                    _ => u64::from(result),
                },
            }
        }
        Call::SetBoundsRect { dc, rect, flags } => {
            let supplied = if rect == 0 { None } else { match read_rect(rect) { Some(value) => Some(value), None => return 0 } };
            with_state(|state| state.set_bounds_rect(dc, supplied, flags)).map(u64::from).unwrap_or(0)
        }
        Call::GetMiterLimit { dc, limit } => match with_state(|state| state.miter_limit(dc)) {
            Err(_) => 0,
            Ok(value) => u64::from(limit == 0 || write_float(limit, value)),
        },
        Call::SetMiterLimit { dc, limit_bits, previous } => {
            match with_state(|state| state.set_miter_limit(dc, limit_bits)) {
                Err(_) => 0,
                Ok(value) => u64::from(previous == 0 || write_float(previous, value)),
            }
        }
        Call::SetPixelFormat { dc, format } => u64::from(with_state(|state| state.set_pixel_format(dc, format)).unwrap_or(false)),
        Call::CreateClientObj { kind } => match with_state(|state| state.create_client_obj(kind)) {
            Err(_) => 0,
            Ok(handle) => match publish_new(handle, |state| state.delete_client_obj(handle)) {
                Ok(()) => u64::from(handle), Err(_) => 0 },
        },
        Call::DeleteClientObj { handle } => {
            if with_state(|state| state.delete_client_obj(handle)).is_err() { return 0; }
            u64::from(retire(handle).is_ok())
        }
        Call::CreateMetafileDc => match with_state(|state| state.create_metafile_dc()) {
            Err(_) => 0,
            Ok(handle) => match publish_new(handle, |state| { state.set_dc_kind(handle, DcKind::EnhMetafile)?; state.delete_object(handle) }) {
                Ok(()) => u64::from(handle), Err(_) => 0 },
        },
        Call::ExtCreatePen { style, width, brush_style, color, style_count, style_bits } => {
            let Some(entries) = read_style_entries(style_bits, style_count) else { return 0; };
            let Ok(color) = syscall::nt_gdi_client::colorref_to_xrgb(color) else { return 0; };
            match with_state(|state| state.create_ext_pen(style, width, brush_style, color, &entries)) {
                Err(_) => failure(ordinal),
                Ok(handle) => match publish_new(handle, |state| state.delete_pen(handle)) {
                    Ok(()) => u64::from(handle), Err(_) => 0 },
            }
        }
    }
}

/// A style array is bounded by the pen owner's own limit, so a hostile count
/// can never drive an unbounded copy. # C: O(N_entries)
fn read_style_entries(address: u64, count: u32) -> Option<alloc::vec::Vec<u32>> {
    let mut entries = alloc::vec::Vec::new();
    if count == 0 { return Some(entries); }
    if address == 0 || count as usize > ipc::win32_gdi::MAX_STYLE_ENTRIES { return None; }
    entries.try_reserve_exact(count as usize).ok()?;
    for index in 0..count as u64 {
        entries.push(uaccess::get_user_u32(address.checked_add(index * 4)?).ok()?);
    }
    Some(entries)
}

fn write_rect(address: u64, rect: Rect) -> bool {
    if address == 0 { return true; }
    let mut bytes = [0u8; RECT_BYTES];
    for (index, field) in [rect.left, rect.top, rect.right, rect.bottom].iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&field.to_le_bytes());
    }
    uaccess::copy_to_user(address, &bytes).is_ok()
}

fn read_rect(address: u64) -> Option<Rect> {
    let field = |offset: u64| uaccess::get_user_u32(address.checked_add(offset)?).ok().map(|value| value as i32);
    Some(Rect { left: field(0)?, top: field(4)?, right: field(8)?, bottom: field(12)? })
}

fn write_float(address: u64, value: f32) -> bool {
    let bytes: [u8; FLOAT_BYTES] = value.to_le_bytes();
    uaccess::copy_to_user(address, &bytes).is_ok()
}
