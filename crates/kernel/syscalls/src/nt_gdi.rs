//! Native GDI object and text-metric services for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as GdiLockClass};
use syscall::nt::{self, NtCall, NtGdiCall, NtGdiFont, NtGdiTextExtent, NtGdiTextMetrics};
#[path = "nt_gdi/client.rs"]
mod client;
#[path = "nt_gdi/lifecycle.rs"]
mod lifecycle;
pub(crate) use lifecycle::initialize_for_current as initialize_client_for_current;
#[path = "nt_gdi/owner.rs"]
mod owner;
use owner::new_entry;
#[path = "nt_gdi/bitmap.rs"]
mod bitmap;
pub(crate) use bitmap::{create_bitmap_for_current, create_pattern_brush_for_current, create_display_dc_for_current};
#[path = "nt_gdi/brush.rs"]
mod brush;
#[path = "nt_gdi/object_query.rs"]
mod object_query;
#[path = "nt_gdi/selected.rs"]
mod selected;
#[path = "nt_gdi/clip.rs"]
mod clip;
mod system_brush;
mod paint_frame;
mod presentation;
use presentation::{capture_window, capture_window_region};
mod paint_seed;
mod position_preserve;
pub(crate) use position_preserve::position_preserve_for_current;
mod region;
pub(crate) use region::set_rect_region_for_current;
pub(crate) use region::{create_region_for_current, create_rect_region_for_current, combine_region_for_current,
    region_snapshot_for_current, replace_region_for_current, region_box_for_current, delete_region_for_current};
pub(crate) use paint_seed::seed_paint_for_current;
mod erase_frame;
pub(crate) use erase_frame::retain_erase_for_current;
mod visibility;
mod dc_query;
mod dc_lease;
mod output;
pub(crate) use output::flush_pending_for_current;
pub(crate) use dc_lease::{get_dc_ex_for_current, release_dc_lease_for_current};
mod pen;
pub(crate) use pen::{create_pen_for_current, select_pen_for_current, pen_line_for_current, pen_rectangle_for_current};
pub(crate) use dc_query::dc_query_value;
#[path = "nt_gdi/dc_caps.rs"]
mod dc_caps;
pub(crate) use dc_caps::contains_dc_for_current;
pub(crate) use visibility::visibility_clip_for_current;
pub(crate) mod nonclient_scroll;
pub(crate) use nonclient_scroll::repaint_nonclient_scroll_for_current;
pub(crate) use system_brush::system_color_brush_for_current;
pub(crate) use lifecycle::delete_object_for_current as delete_paint_dc_current;
pub(crate) use lifecycle::create_dc_for_current as create_paint_dc_for_current;
pub(crate) use clip::{intersect_clip_rect_for_current, get_app_clip_box_for_current, app_clip_box_snapshot_for_current, set_paint_clip_for_current, set_paint_region_for_current};
pub(crate) use selected::selected_object_current;
pub(crate) use object_query::{create_font_record_for_current, get_object_w_for_current};
pub(crate) use brush::{create_solid_brush_for_current, select_brush_for_current, pat_blt_for_current, set_dc_brush_color_for_current};
#[path = "nt_gdi/text.rs"]
mod text;
pub(crate) use text::{text_snapshot_for_current, text_metrics_for_current,
    set_text_attribute_for_current, set_text_position_for_current, blend_surface_for_current};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;

struct GdiEntry { group: Weak<sched::thread_group::ThreadGroup>, state: ipc::win32_gdi::GdiManager, client: Option<client::ClientBinding>, output_pump: output::OutputPump }
static GDI: Spinlock<Vec<GdiEntry>, GdiLockClass> = Spinlock::new(Vec::new());

/// Dispatch GDI object and text metric calls against the current NT process.
/// # C: O(N_process_gdi_states + N_objects + N_text)
pub fn dispatch(call: NtCall) -> Option<u64> {
    let operation = nt::decode_gdi(call).ok()?;
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    match operation {
        NtGdiCall::CreateDc { width, height } => return Some(lifecycle::create_dc_for_current(width, height).map(u64::from).unwrap_or(STATUS_INVALID_PARAMETER)),
        NtGdiCall::DeleteObject { handle } => return Some(lifecycle::delete_object_for_current(handle).map(|()| STATUS_SUCCESS).unwrap_or(STATUS_INVALID_HANDLE)),
        NtGdiCall::SelectFont { dc, font } => return Some(lifecycle::select_font_for_current(dc, font).map(u64::from).unwrap_or(STATUS_INVALID_HANDLE)),
        NtGdiCall::CreateFont { font } => return Some(create_font(font)),
        _ => {}
    }
    // Snapshot GUI-owned metadata before taking GDI. GUI destruction takes
    // GUI then performs deferred GDI cleanup; presentation must never acquire
    // the locks in the reverse order.
    let present = match operation {
        NtGdiCall::PresentWindow { hwnd, .. } => super::nt_window::window_rect_for_current(hwnd),
        _ => None,
    };
    let present_region = match operation {
        NtGdiCall::PresentWindowRegion { hwnd, .. } => super::nt_window::paint::presentation_for_current(hwnd),
        _ => None,
    };
    if let NtGdiCall::PresentWindow { hwnd, dc } = operation {
        if present.is_none() { return Some(STATUS_INVALID_HANDLE); }
        let dimensions = {
            let entries = GDI.lock();
            entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))
                .and_then(|entry| entry.state.surface(dc).map(|(width, height, _)| (width, height)))
        };
        let Some((width, height)) = dimensions else { return Some(STATUS_INVALID_HANDLE); };
        if lifecycle::acquire_window_dc_for_current(hwnd, width, height).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GDI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)));
    let index = index.unwrap_or_else(|| {
        entries.push(new_entry(&group));
        entries.len() - 1
    });
    let state = &mut entries[index].state;
    // Snapshot while GDI owns the pixels, then release its lock before the
    // transport can sleep waiting for the desktop's acknowledgement.
    let frame = match operation {
        NtGdiCall::PresentWindow { hwnd, dc } => Some(capture_window(state, hwnd, dc, present)),
        NtGdiCall::PresentWindowRegion { hwnd, dc, left, top, right, bottom } =>
            Some(capture_window_region(state, hwnd, dc, left, top, right, bottom, present_region)),
        _ => None,
    };
    if let Some(frame) = frame {
        drop(entries);
        return Some(output::submit_prepared_for_current(frame));
    }
    match operation {
        NtGdiCall::CreateDc { .. } | NtGdiCall::DeleteObject { .. } | NtGdiCall::CreateFont { .. } | NtGdiCall::SelectFont { .. } => unreachable!("lifetime operations precede GDI lock"),
        NtGdiCall::GetTextMetrics { dc, metrics } => Some(get_metrics(state, dc, metrics)),
        NtGdiCall::GetTextExtent { dc, count, text, extent } => Some(get_extent(state, dc, count, text, extent)),
        NtGdiCall::FillRect { dc, left, top, right, bottom, color } => Some(match state.fill_rect(dc, ipc::win32_gdi::Rect { left, top, right, bottom }, color) { Ok(()) => STATUS_SUCCESS, Err(_) => STATUS_INVALID_HANDLE }),
        NtGdiCall::BlitSurface { dc, pixels, x, y, width, height, stride } => Some(blit_surface(state, dc, pixels, x, y, width, height, stride)),
        NtGdiCall::BitBltSurface { dst, src, dst_x, dst_y, src_x, src_y, width, height } => Some(match state.bitblt(dst, dst_x, dst_y, src, src_x, src_y, width, height) { Ok(()) => STATUS_SUCCESS, Err(ipc::win32_gdi::GdiError::NoSuchObject) => STATUS_INVALID_HANDLE, Err(_) => STATUS_INVALID_PARAMETER }),
        NtGdiCall::PresentSurface { dc, x, y } => Some(present_surface(state, dc, x, y)),
        NtGdiCall::PresentWindow { .. } | NtGdiCall::PresentWindowRegion { .. } => unreachable!("presentation handled outside GDI lock"),
    }
}

/// Return the process GDI owner's stock dialog metrics for User32. # C: O(N_process_gdi_states)
pub fn dialog_base_units() -> Option<(i32, i32)> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GDI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)));
    let index = index.unwrap_or_else(|| {
        entries.push(new_entry(&group));
        entries.len() - 1
    });
    Some(entries[index].state.dialog_base_units())
}

/// Acquire the canonical per-window DC owned by the current NT process. # C: O(N_process_gdi_states + N_windows)
pub fn acquire_window_dc_for_current(hwnd: u32, width: i32, height: i32) -> u64 {
    lifecycle::acquire_window_dc_for_current(hwnd, width, height).map(u64::from).unwrap_or(STATUS_INVALID_PARAMETER)
}

/// Validate one ReleaseDC lease against the canonical window owner. # C: O(N_process_gdi_states + N_windows)
pub fn release_window_dc_for_current(hwnd: u32, dc: u32) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GDI.lock();
    let Some(entry) = entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return STATUS_INVALID_HANDLE; };
    match entry.state.release_window_dc(hwnd, dc) {
        Ok(()) => STATUS_SUCCESS,
        Err(_) => STATUS_INVALID_HANDLE,
    }
}

/// Remove a window DC when its canonical HWND is destroyed. # C: O(N_process_gdi_states + N_windows)
pub fn destroy_window_dc_for_current(hwnd: u32) {
    let _ = dc_lease::revoke_window_leases_for_current(hwnd);
    let Some(cur) = sched::live::current() else { return; };
    if !cur.is_nt_personality() { return; }
    let group = Arc::clone(&cur.thread_group);
    let handle = {
        let entries = GDI.lock();
        entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&group))).and_then(|entry| entry.state.window_dc(hwnd))
    };
    if let Some(handle) = handle { let _ = lifecycle::destroy_window_dc_for_current(hwnd, handle); }
}

fn blit_surface(state: &mut ipc::win32_gdi::GdiManager, dc: u32, pixels: syscall::UserPtr<u8>, x: i32, y: i32, width: u32, height: u32, stride: u32) -> u64 {
    let Some(words) = (height as usize).checked_mul(stride as usize) else { return STATUS_INVALID_PARAMETER; };
    if width == 0 || height == 0 || width > i32::MAX as u32 || height > i32::MAX as u32
        || stride < width || stride > i32::MAX as u32 || words > 16 * 1024 * 1024 { return STATUS_INVALID_PARAMETER; }
    let Some(bytes_len) = words.checked_mul(core::mem::size_of::<u32>()) else { return STATUS_INVALID_PARAMETER; };
    let mut bytes = alloc::vec![0u8; bytes_len];
    if uaccess::copy_from_user(&mut bytes, pixels.as_u64()).is_err() { return STATUS_INVALID_PARAMETER; }
    let mut values = alloc::vec![0u32; words];
    for (index, value) in values.iter_mut().enumerate() { let offset = index * 4; *value = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()); }
    match state.blit_pixels(dc, x, y, width as i32, height as i32, stride as i32, &values) { Ok(()) => STATUS_SUCCESS, Err(_) => STATUS_INVALID_HANDLE }
}

fn present_surface(state: &ipc::win32_gdi::GdiManager, dc: u32, x: i32, y: i32) -> u64 {
    let Some((width, height, pixels)) = state.surface(dc) else { return STATUS_INVALID_HANDLE; };
    if drm::node::present_primary_surface(pixels, width as u32, height as u32, x, y,
        drm::node::DamageRect::full(width as u32, height as u32)) { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER }
}


fn submit_frame(frame: Result<syscall::nt_compositor::Record, u64>) -> u64 {
    let frame = match frame { Ok(frame) => frame, Err(status) => return status };
    let ticket = match crate::nt_compositor::enqueue_current(frame.header.opcode, frame.header.hwnd, frame.payload) {
        Ok(ticket) => ticket, Err(_) => return STATUS_INVALID_PARAMETER,
    };
    match crate::nt_compositor::wait_completion_current(ticket, 5_000_000_000) {
        Ok(crate::nt_compositor::Completion::Presented) => {
            crate::nt_milestone::desktop_ack();
            STATUS_SUCCESS
        }
        _ => STATUS_INVALID_PARAMETER,
    }
}

fn create_font(pointer: syscall::UserPtr<NtGdiFont>) -> u64 {
    let mut bytes = [0u8; core::mem::size_of::<NtGdiFont>()];
    if uaccess::copy_from_user(&mut bytes, pointer.as_u64()).is_err() { return STATUS_INVALID_PARAMETER; }
    let field = |index: usize| i32::from_le_bytes(bytes[index..index + 4].try_into().unwrap());
    match lifecycle::create_font_for_current(ipc::win32_gdi::Font { height: field(0), width: field(4), weight: field(8), italic: field(12) != 0 }) {
        Ok(handle) => handle as u64, Err(_) => STATUS_INVALID_PARAMETER,
    }
}

fn get_metrics(state: &ipc::win32_gdi::GdiManager, dc: u32, pointer: syscall::UserPtr<NtGdiTextMetrics>) -> u64 {
    let Ok(value) = state.text_metrics(dc) else { return STATUS_INVALID_HANDLE; };
    let native = NtGdiTextMetrics { height: value.height, ascent: value.ascent, descent: value.descent, average_width: value.average_width, max_width: value.max_width, character_width: value.character_width };
    let bytes = [native.height.to_le_bytes(), native.ascent.to_le_bytes(), native.descent.to_le_bytes(), native.average_width.to_le_bytes(), native.max_width.to_le_bytes(), native.character_width.to_le_bytes()];
    let mut raw = [0u8; 24];
    for (index, field) in bytes.iter().enumerate() { raw[index * 4..index * 4 + 4].copy_from_slice(field); }
    if uaccess::copy_to_user(pointer.as_u64(), &raw).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
}

fn get_extent(state: &ipc::win32_gdi::GdiManager, dc: u32, count: u32, text: syscall::UserPtr<u16>, pointer: syscall::UserPtr<NtGdiTextExtent>) -> u64 {
    let mut unit = [0u8; 2];
    for index in 0..count { let Some(address) = text.as_u64().checked_add(index as u64 * 2) else { return STATUS_INVALID_PARAMETER; }; if uaccess::copy_from_user(&mut unit, address).is_err() { return STATUS_INVALID_PARAMETER; } }
    let Ok(value) = state.text_extent(dc, count) else { return STATUS_INVALID_PARAMETER; };
    let native = NtGdiTextExtent { width: value.width, height: value.height };
    let raw = [native.width.to_le_bytes(), native.height.to_le_bytes()];
    let mut bytes = [0u8; 8];
    for (index, field) in raw.iter().enumerate() { bytes[index * 4..index * 4 + 4].copy_from_slice(field); }
    if uaccess::copy_to_user(pointer.as_u64(), &bytes).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
}
