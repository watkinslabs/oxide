use super::*;

/// Allocate an HMENU in the canonical per-process menu owner. # C: O(N_process_gui_states)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn create_menu_for_current(popup: bool) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| { entries.push(new_entry(&group)); entries.len() - 1 });
    let result = if popup { entries[index].menus.create_popup() } else { entries[index].menus.create() };
    result.map(|menu| menu.raw() as u64).unwrap_or(STATUS_INVALID_PARAMETER)
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) fn destroy_menu_for_current(raw: u64) -> u64 {
    let Some(menu) = u32::try_from(raw).ok().and_then(ipc::win32_menu::MenuId::from_raw) else { return STATUS_INVALID_PARAMETER; };
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return STATUS_INVALID_PARAMETER; };
    if entries[index].menus.destroy(menu).is_err() { return STATUS_INVALID_PARAMETER; }
    entries[index].state.clear_menu(menu.raw());
    STATUS_SUCCESS
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) fn check_menu_item_for_current(raw: u64, id: u64, flags: u64) -> u64 {
    let (Some(menu), Some(id), Some(flags)) = (u32::try_from(raw).ok().and_then(ipc::win32_menu::MenuId::from_raw), u32::try_from(id).ok(), u32::try_from(flags).ok()) else { return ipc::win32_menu::MENU_NOT_FOUND as u64; };
    let Some(cur) = sched::live::current() else { return ipc::win32_menu::MENU_NOT_FOUND as u64; };
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return ipc::win32_menu::MENU_NOT_FOUND as u64; };
    entries[index].menus.check(menu, id, flags).unwrap_or(ipc::win32_menu::MENU_NOT_FOUND) as u64
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) fn enable_menu_item_for_current(raw: u64, id: u64, flags: u64) -> u64 {
    let (Some(menu), Some(id), Some(flags)) = (u32::try_from(raw).ok().and_then(ipc::win32_menu::MenuId::from_raw), u32::try_from(id).ok(), u32::try_from(flags).ok()) else { return ipc::win32_menu::MENU_NOT_FOUND as u64; };
    let Some(cur) = sched::live::current() else { return ipc::win32_menu::MENU_NOT_FOUND as u64; };
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return ipc::win32_menu::MENU_NOT_FOUND as u64; };
    entries[index].menus.enable(menu, id, flags).unwrap_or(ipc::win32_menu::MENU_NOT_FOUND) as u64
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) fn delete_menu_item_for_current(raw: u64, id: u64, flags: u64) -> u64 {
    let (Some(menu), Some(id), Some(flags)) = (u32::try_from(raw).ok().and_then(ipc::win32_menu::MenuId::from_raw), u32::try_from(id).ok(), u32::try_from(flags).ok()) else { return STATUS_INVALID_PARAMETER; };
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return STATUS_INVALID_PARAMETER; };
    if entries[index].menus.delete(menu, id, flags).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) fn remove_menu_item_for_current(raw: u64, id: u64, flags: u64) -> u64 {
    let (Some(menu), Some(id), Some(flags)) = (u32::try_from(raw).ok().and_then(ipc::win32_menu::MenuId::from_raw), u32::try_from(id).ok(), u32::try_from(flags).ok()) else { return STATUS_INVALID_PARAMETER; };
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return STATUS_INVALID_PARAMETER; };
    if entries[index].menus.remove(menu, id, flags).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) fn set_window_menu_for_current(hwnd: u64, menu: Option<u32>) -> Result<Option<u32>, ()> {
    let Some(cur) = sched::live::current() else { return Err(()); };
    if !cur.is_nt_personality() || hwnd > u32::MAX as u64 { return Err(()); }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return Err(()); };
    if let Some(raw) = menu { let Some(menu) = ipc::win32_menu::MenuId::from_raw(raw) else { return Err(()); }; if !entries[index].menus.contains(menu) { return Err(()); } }
    entries[index].state.set_menu(ipc::win32_window::WindowId::from_raw(hwnd as u32).ok_or(())?, menu).map_err(|_| ())
}

/// Return the item count from the canonical HMENU owner. # C: O(N_process_gui_states + N_items)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn menu_item_count_for_current(raw: u64) -> u64 {
    let Some(menu) = u32::try_from(raw).ok().and_then(ipc::win32_menu::MenuId::from_raw) else { return u64::MAX; };
    let Some(cur) = sched::live::current() else { return u64::MAX; };
    if !cur.is_nt_personality() { return u64::MAX; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return u64::MAX; };
    entries[index].menus.count(menu).map(|count| count as u64).unwrap_or(u64::MAX)
}

/// Resolve one menu-bar item rectangle from the canonical HWND/menu owners. # C: O(N_process_gui_states + N_items)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn menu_item_rect_for_current(hwnd: u64, raw: u64, position: u64) -> Option<ipc::win32_menu::MenuRect> {
    let hwnd = ipc::win32_window::WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
    let menu = ipc::win32_menu::MenuId::from_raw(u32::try_from(raw).ok()?)?;
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    if entries[index].state.menu(hwnd) != Some(menu.raw()) { return None; }
    let rect = entries[index].state.rect(hwnd)?;
    let origin = ipc::win32_menu::MenuRect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom };
    entries[index].menus.bar_item_rect(menu, usize::try_from(position).ok()?, origin, &ipc::win32_gdi::menu_bar_metrics()).ok()
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) fn window_menu_for_current(hwnd: u64) -> Option<u64> {
    let hwnd = ipc::win32_window::WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    entries[index].state.menu(hwnd).map(|menu| menu as u64)
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) fn menu_bar_rect_for_current(hwnd: u64) -> Option<ipc::win32_menu::MenuRect> {
    let hwnd_id = ipc::win32_window::WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    let menu = entries[index].state.menu(hwnd_id)?;
    let menu = ipc::win32_menu::MenuId::from_raw(menu)?;
    let rect = entries[index].state.rect(hwnd_id)?;
    let origin = ipc::win32_menu::MenuRect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom };
    entries[index].menus.bar_rect(menu, origin, &ipc::win32_gdi::menu_bar_metrics()).ok()
}

/// Resolve menu geometry for Wine's explicit `NtUserDrawMenuBarTemp` handle.
/// The HWND rectangle and menu item layout remain owned by their native
/// managers; this helper only joins those canonical records.
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn menu_bar_rect_for_current_menu(hwnd: u64, raw_menu: u64) -> Option<ipc::win32_menu::MenuRect> {
    let hwnd = ipc::win32_window::WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
    let menu = ipc::win32_menu::MenuId::from_raw(u32::try_from(raw_menu).ok()?)?;
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    if !entries[index].menus.contains(menu) { return None; }
    let rect = entries[index].state.rect(hwnd)?;
    let origin = ipc::win32_menu::MenuRect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom };
    entries[index].menus.bar_rect(menu, origin, &ipc::win32_gdi::menu_bar_metrics()).ok()
}

/// Redrawing a window's menu bar is a frame change: it invalidates the whole
/// window, nonclient band included, so the bar is repainted from WM_NCPAINT.
/// A client-only invalidation leaves the bar band untouched.
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn draw_menu_bar_for_current(hwnd: u64) -> u64 {
    let Some(hwnd) = ipc::win32_window::WindowId::from_raw(u32::try_from(hwnd).ok().unwrap_or(u32::MAX)) else { return STATUS_INVALID_PARAMETER; };
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return STATUS_INVALID_HANDLE; };
    if entries[index].state.menu(hwnd).is_none() { return STATUS_SUCCESS; }
    if entries[index].state.redraw_tree(hwnd, None, ipc::win32_window::FRAME_REDRAW, |_, _, region| region.try_copy()).is_err() { return STATUS_INVALID_HANDLE; }
    STATUS_SUCCESS
}
