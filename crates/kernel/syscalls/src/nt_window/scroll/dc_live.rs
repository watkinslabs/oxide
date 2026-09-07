//! Live pixel scrolling for a device context and for a window.
use super::dc_raw::*;
use crate::nt_window::{redraw, GUI};
use alloc::sync::Arc;
use ipc::win32_window::{PaintRegion, WindowRect};

/// `GetDCEx` with no cached-DC restriction, which the scroll uses when the
/// caller has not refused the DC cache.
const DCX_CACHE: u32 = 0x0000_0002;

/// Route the two scroll entries. # C: O(N_windows + moved pixels); # Sleeps: yes
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    let arg = |index: usize| args.get(index).copied().unwrap_or(0);
    match ordinal {
        SCROLL_DC => Some(scroll_dc(arg(0), arg(1) as i32, arg(2) as i32, arg(3), arg(4), arg(5), arg(6))),
        SCROLL_WINDOW_EX => Some(scroll_window(arg(0), arg(1) as i32, arg(2) as i32, arg(3), arg(4), arg(5), arg(6), arg(7) as u32)),
        _ => None,
    }
}

fn read_rect(address: u64) -> Option<WindowRect> {
    if address == 0 { return None; }
    let mut bytes = [0u8; 16];
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    let field = |index: usize| i32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
    Some(WindowRect { left: field(0), top: field(1), right: field(2), bottom: field(3) })
}

fn write_rect(address: u64, rect: WindowRect) -> bool {
    if address == 0 { return true; }
    let mut bytes = [0u8; 16];
    for (index, value) in [rect.left, rect.top, rect.right, rect.bottom].into_iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    uaccess::copy_to_user(address, &bytes).is_ok()
}

/// Move the named pixels within one device context and report what the move
/// left needing repaint. # C: O(moved pixels)
fn scroll_dc(dc: u64, dx: i32, dy: i32, scroll: u64, clip: u64, update_rgn: u64, update_rect: u64) -> u64 {
    let Ok((_, clip_box)) = crate::nt_gdi::app_clip_box_snapshot_for_current(dc) else { return 0; };
    let clip_box = WindowRect { left: clip_box.left, top: clip_box.top, right: clip_box.right, bottom: clip_box.bottom };
    let plan = plan(clip_box, read_rect(scroll), read_rect(clip), dx, dy);
    if !is_empty(plan.source) && crate::nt_gdi::scroll_surface_for_current(dc, plan.source, dx, dy).is_err() { return 0; }
    let Ok(region) = update_region(plan) else { return 0; };
    if update_rgn != 0 {
        let Ok(copy) = region.try_copy() else { return 0; };
        if crate::nt_gdi::replace_region_for_current(update_rgn, copy).is_err() { return 0; }
    }
    if !write_rect(update_rect, region.bounds().unwrap_or(WindowRect { left: 0, top: 0, right: 0, bottom: 0 })) { return 0; }
    1
}

fn client_rect(hwnd: u64) -> Option<WindowRect> {
    let window = u32::try_from(hwnd).ok().and_then(ipc::win32_window::WindowId::from_raw)?;
    let cur = sched::live::current().filter(|cur| cur.is_nt_personality())?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    let client = entry.state.client_rect(window)?;
    Some(WindowRect { left: 0, top: 0, right: client.right - client.left, bottom: client.bottom - client.top })
}

/// Scroll a window's client area, then invalidate what the move left behind.
/// # C: O(N_windows + moved pixels); # Sleeps: yes
fn scroll_window(hwnd: u64, dx: i32, dy: i32, rect: u64, clip: u64, update_rgn: u64, update_rect: u64, flags: u32) -> u64 {
    let Some(client) = client_rect(hwnd) else { return ipc::win32_gdi::CLIP_ERROR as u64; };
    let area = read_rect(rect).map_or(client, |named| intersect(client, named));
    let clip_area = read_rect(clip).map_or(client, |named| intersect(client, named));
    if is_empty(clip_area) || (dx == 0 && dy == 0) {
        if update_rgn != 0 { let _ = crate::nt_gdi::replace_region_for_current(update_rgn, PaintRegion::default()); }
        write_rect(update_rect, WindowRect { left: 0, top: 0, right: 0, bottom: 0 });
        return ipc::win32_gdi::NULL_REGION as u64;
    }
    let dcx: u32 = if flags & SW_NODCCACHE != 0 { 0 } else { DCX_CACHE };
    let Ok(target) = u32::try_from(hwnd) else { return ipc::win32_gdi::CLIP_ERROR as u64; };
    let dc = crate::nt_gdi::get_dc_ex_for_current(target, 0, dcx as u32);
    if dc == 0 { return ipc::win32_gdi::CLIP_ERROR as u64; }
    let plan = plan(clip_area, Some(area), Some(clip_area), dx, dy);
    let moved = is_empty(plan.source) || crate::nt_gdi::scroll_surface_for_current(dc, plan.source, dx, dy).is_ok();
    let _ = u32::try_from(dc).map(crate::nt_gdi::release_dc_lease_for_current);
    if !moved { return ipc::win32_gdi::CLIP_ERROR as u64; }
    let Ok(mut region) = update_region(plan) else { return ipc::win32_gdi::CLIP_ERROR as u64; };
    if overshoots(area, dx, dy) {
        if let Ok(extra) = PaintRegion::from_rect(intersect(offset(area, dx, dy), clip_area)) { let _ = region.union(&extra); }
    }
    let bounds = region.bounds().unwrap_or(WindowRect { left: 0, top: 0, right: 0, bottom: 0 });
    let complexity = ipc::win32_window::region_complexity(&region);
    if update_rgn != 0 {
        let Ok(copy) = region.try_copy() else { return ipc::win32_gdi::CLIP_ERROR as u64; };
        if crate::nt_gdi::replace_region_for_current(update_rgn, copy).is_err() { return ipc::win32_gdi::CLIP_ERROR as u64; }
    }
    write_rect(update_rect, bounds);
    if wants_update(update_rgn, update_rect, flags) && !is_empty(bounds) {
        invalidate(hwnd, &region, redraw_flags(flags));
    }
    if flags & SW_SCROLLCHILDREN != 0 { move_children(hwnd, dx, dy); }
    complexity as u64
}

/// Invalidate the region the scroll left behind through the redraw owner.
/// # C: O(N_windows); # Sleeps: yes
fn invalidate(hwnd: u64, region: &PaintRegion, flags: u32) {
    let Ok(copy) = region.try_copy() else { return; };
    let Some(cur) = sched::live::current().filter(|cur| cur.is_nt_personality()) else { return; };
    let Some(window) = u32::try_from(hwnd).ok().and_then(ipc::win32_window::WindowId::from_raw) else { return; };
    {
        let mut entries = GUI.lock();
        let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) else { return; };
        if entry.state.redraw_damage(window, Some(&copy), flags, false).is_err() { return; }
    }
    let _ = redraw::for_current(hwnd, 0, 0, flags & !ipc::win32_window::RDW_INVALIDATE);
}

/// Every child moves with the content it sits on. # C: O(N_windows); # Sleeps: yes
fn move_children(hwnd: u64, dx: i32, dy: i32) {
    let Some(parent) = u32::try_from(hwnd).ok().and_then(ipc::win32_window::WindowId::from_raw) else { return; };
    let Some(cur) = sched::live::current().filter(|cur| cur.is_nt_personality()) else { return; };
    let children = {
        let entries = GUI.lock();
        match entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) {
            Some(entry) => entry.state.window_handles().into_iter()
                .filter(|id| entry.state.get(*id).is_some_and(|record| record.parent == Some(parent)))
                .filter_map(|id| entry.state.rect(id).map(|rect| (id, rect))).collect::<alloc::vec::Vec<_>>(),
            None => alloc::vec::Vec::new(),
        }
    };
    for (child, rect) in children {
        let moved = offset(rect, dx, dy);
        let _ = crate::nt_window::position::position_apply_for_current(crate::nt_wine_window::position::Request {
            hwnd: child.raw() as u64, rect: moved, order: None, visible: None,
            flags: SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOSIZE });
    }
}

const SWP_NOSIZE: u32 = 0x0001;
const SWP_NOZORDER: u32 = 0x0004;
const SWP_NOACTIVATE: u32 = 0x0010;
