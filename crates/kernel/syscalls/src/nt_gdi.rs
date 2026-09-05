//! Native GDI object and text-metric services for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as GdiLockClass};
use syscall::nt::{self, NtCall, NtGdiCall, NtGdiFont, NtGdiTextExtent, NtGdiTextMetrics};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;

struct GdiEntry { group: Weak<sched::thread_group::ThreadGroup>, state: ipc::win32_gdi::GdiManager }
static GDI: Spinlock<Vec<GdiEntry>, GdiLockClass> = Spinlock::new(Vec::new());

/// Dispatch GDI object and text metric calls against the current NT process.
/// # C: O(N_process_gdi_states + N_objects + N_text)
pub fn dispatch(call: NtCall) -> Option<u64> {
    let operation = nt::decode_gdi(call).ok()?;
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GDI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)));
    let index = index.unwrap_or_else(|| {
        entries.push(GdiEntry { group: Arc::downgrade(&group), state: ipc::win32_gdi::GdiManager::new() });
        entries.len() - 1
    });
    let state = &mut entries[index].state;
    match operation {
        NtGdiCall::CreateDc { width, height } => Some(match state.create_dc(width, height) { Ok(handle) => handle as u64, Err(_) => STATUS_INVALID_PARAMETER }),
        NtGdiCall::DeleteObject { handle } => Some(match state.delete_object(handle) { Ok(()) => STATUS_SUCCESS, Err(_) => STATUS_INVALID_HANDLE }),
        NtGdiCall::CreateFont { font } => Some(create_font(state, font)),
        NtGdiCall::SelectFont { dc, font } => Some(match state.select_font(dc, font) { Ok(previous) => previous as u64, Err(_) => STATUS_INVALID_HANDLE }),
        NtGdiCall::GetTextMetrics { dc, metrics } => Some(get_metrics(state, dc, metrics)),
        NtGdiCall::GetTextExtent { dc, count, text, extent } => Some(get_extent(state, dc, count, text, extent)),
        NtGdiCall::FillRect { dc, left, top, right, bottom, color } => Some(match state.fill_rect(dc, ipc::win32_gdi::Rect { left, top, right, bottom }, color) { Ok(()) => STATUS_SUCCESS, Err(_) => STATUS_INVALID_HANDLE }),
        NtGdiCall::BlitSurface { dc, pixels, x, y, width, height, stride } => Some(blit_surface(state, dc, pixels, x, y, width, height, stride)),
        NtGdiCall::BitBltSurface { dst, src, dst_x, dst_y, src_x, src_y, width, height } => Some(match state.bitblt(dst, dst_x, dst_y, src, src_x, src_y, width, height) { Ok(()) => STATUS_SUCCESS, Err(ipc::win32_gdi::GdiError::NoSuchObject) => STATUS_INVALID_HANDLE, Err(_) => STATUS_INVALID_PARAMETER }),
        NtGdiCall::PresentSurface { dc, x, y } => Some(present_surface(state, dc, x, y)),
        NtGdiCall::PresentWindow { hwnd, dc } => Some(present_window(state, hwnd, dc)),
        NtGdiCall::PresentWindowRegion { hwnd, dc, left, top, right, bottom } => Some(present_window_region(state, hwnd, dc, left, top, right, bottom)),
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
        entries.push(GdiEntry { group: Arc::downgrade(&group), state: ipc::win32_gdi::GdiManager::new() });
        entries.len() - 1
    });
    Some(entries[index].state.dialog_base_units())
}

/// Acquire the canonical per-window DC owned by the current NT process. # C: O(N_process_gdi_states + N_windows)
pub fn acquire_window_dc_for_current(hwnd: u32, width: i32, height: i32) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GDI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)));
    let index = index.unwrap_or_else(|| {
        entries.push(GdiEntry { group: Arc::downgrade(&group), state: ipc::win32_gdi::GdiManager::new() });
        entries.len() - 1
    });
    match entries[index].state.acquire_window_dc(hwnd, width, height) {
        Ok(handle) => handle as u64,
        Err(_) => STATUS_INVALID_PARAMETER,
    }
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
    let Some(cur) = sched::live::current() else { return; };
    if !cur.is_nt_personality() { return; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GDI.lock();
    if let Some(entry) = entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) { let _ = entry.state.destroy_window_dc(hwnd); }
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
    if drv_virtio_gpu::post_init::present_window_pixels(pixels, width as u32, height as u32, x, y) { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER }
}

fn present_window(state: &ipc::win32_gdi::GdiManager, hwnd: u32, dc: u32) -> u64 {
    let Some((rect, visible)) = super::nt_window::window_rect_for_current(hwnd) else { return STATUS_INVALID_HANDLE; };
    if !visible || rect.right <= rect.left || rect.bottom <= rect.top { return STATUS_INVALID_PARAMETER; }
    let Some((width, height, pixels)) = state.surface(dc) else { return STATUS_INVALID_HANDLE; };
    if width <= 0 || height <= 0 { return STATUS_INVALID_PARAMETER; }
    if drv_virtio_gpu::post_init::present_window_pixels(pixels, width as u32, height as u32, rect.left, rect.top) { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER }
}

fn present_window_region(state: &ipc::win32_gdi::GdiManager, hwnd: u32, dc: u32, left: i32, top: i32, right: i32, bottom: i32) -> u64 {
    let Some((rect, visible)) = super::nt_window::window_rect_for_current(hwnd) else { return STATUS_INVALID_HANDLE; };
    if !visible || rect.right <= rect.left || rect.bottom <= rect.top || right <= left || bottom <= top { return STATUS_INVALID_PARAMETER; }
    let Some((width, height, pixels)) = state.surface(dc) else { return STATUS_INVALID_HANDLE; };
    if width <= 0 || height <= 0 || right > width || bottom > height { return STATUS_INVALID_PARAMETER; }
    let Some(x) = rect.left.checked_add(left) else { return STATUS_INVALID_PARAMETER; };
    let Some(y) = rect.top.checked_add(top) else { return STATUS_INVALID_PARAMETER; };
    if drv_virtio_gpu::post_init::present_window_pixels_region(pixels, width as u32, height as u32, x, y, left as u32, top as u32, right as u32, bottom as u32) { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER }
}

fn create_font(state: &mut ipc::win32_gdi::GdiManager, pointer: syscall::UserPtr<NtGdiFont>) -> u64 {
    let mut bytes = [0u8; core::mem::size_of::<NtGdiFont>()];
    if uaccess::copy_from_user(&mut bytes, pointer.as_u64()).is_err() { return STATUS_INVALID_PARAMETER; }
    let field = |index: usize| i32::from_le_bytes(bytes[index..index + 4].try_into().unwrap());
    match state.create_font(ipc::win32_gdi::Font { height: field(0), width: field(4), weight: field(8), italic: field(12) != 0 }) {
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
