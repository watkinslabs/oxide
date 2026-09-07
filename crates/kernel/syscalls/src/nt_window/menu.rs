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
    let (width, height, bar_height) = (ipc::win32_gdi::MENU_CHAR_WIDTH, ipc::win32_gdi::MENU_CHAR_HEIGHT, ipc::win32_gdi::MENU_BAR_HEIGHT);
    entries[index].menus.bar_item_rect(menu, usize::try_from(position).ok()?, origin, width, height, bar_height).ok()
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
    entries[index].menus.bar_rect(menu, origin, ipc::win32_gdi::MENU_CHAR_WIDTH, ipc::win32_gdi::MENU_CHAR_HEIGHT, ipc::win32_gdi::MENU_BAR_HEIGHT).ok()
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
    entries[index].menus.bar_rect(menu, origin, ipc::win32_gdi::MENU_CHAR_WIDTH, ipc::win32_gdi::MENU_CHAR_HEIGHT, ipc::win32_gdi::MENU_BAR_HEIGHT).ok()
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

/// Apply or query Wine's x86-64 MENUITEMINFO transaction against the one
/// canonical process menu owner. # C: O(N_process_gui_states + N_items)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn thunked_menu_item_info(raw: u64, position: u64, flags: u64, method: u64, info: u64) -> u64 {
    use ipc::win32_menu::item_info;
    const SET: u64 = 0;
    const INSERT: u64 = 1;
    const GET_ID: u64 = 5;
    const GET_INFO_W: u64 = 6;
    const GET_STATE: u64 = 7;
    const GET_SUBMENU: u64 = 8;
    const BY_POSITION: u32 = ipc::win32_menu::MF_BYPOSITION;
    let (Some(menu), Some(position), Some(flags), Some(method)) = (u32::try_from(raw).ok().and_then(ipc::win32_menu::MenuId::from_raw), u32::try_from(position).ok(), u32::try_from(flags).ok(), u64::try_from(method).ok()) else { return ipc::win32_menu::MENU_NOT_FOUND as u64; };
    let Some(cur) = sched::live::current() else { return ipc::win32_menu::MENU_NOT_FOUND as u64; };
    if !cur.is_nt_personality() { return ipc::win32_menu::MENU_NOT_FOUND as u64; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return ipc::win32_menu::MENU_NOT_FOUND as u64; };
    if method == GET_ID || method == GET_STATE || method == GET_SUBMENU {
        let Ok(item) = entries[index].menus.item(menu, position, flags) else { return ipc::win32_menu::MENU_NOT_FOUND as u64; };
        return if method == GET_ID { if item.submenu.is_some() { u32::MAX as u64 } else { item.id as u64 } } else if method == GET_STATE { item.state as u64 } else { item.submenu.unwrap_or(0) as u64 };
    }
    let mut image = [0u8; item_info::MENUITEMINFO_BYTES];
    if info == 0 || uaccess::copy_from_user(&mut image, info).is_err() { return 0; }
    let Some(fields) = item_info::ItemInfo::decode(&image) else { return 0; };
    let field = |offset: usize| info.checked_add(offset as u64);
    if method == GET_INFO_W {
        let Ok(item) = entries[index].menus.item(menu, position, flags) else { return 0; };
        let store = |offset: usize, bytes: &[u8]| field(offset).is_some_and(|address| uaccess::copy_to_user(address, bytes).is_ok());
        if fields.mask & item_info::MIIM_FTYPE != 0 && !store(item_info::OFFSET_TYPE, &(item.state & item_info::MENUITEMINFO_TYPE_MASK).to_le_bytes()) { return 0; }
        if fields.mask & item_info::MIIM_STATE != 0 && !store(item_info::OFFSET_STATE, &(item.state & item_info::MENUITEMINFO_STATE_MASK).to_le_bytes()) { return 0; }
        if fields.mask & item_info::MIIM_ID != 0 && !store(item_info::OFFSET_ID, &item.id.to_le_bytes()) { return 0; }
        // The reference clears the submenu field of every query that did not
        // ask for it, so a caller never reads a stale handle out of its own
        // block.
        if !store(item_info::OFFSET_SUBMENU, &u64::from(if fields.mask & item_info::MIIM_SUBMENU != 0 { item.submenu.unwrap_or(0) } else { 0 }).to_le_bytes()) { return 0; }
        if fields.mask & (item_info::MIIM_STRING | item_info::MIIM_TYPE) != 0 {
            let units = item.text.iter().position(|unit| *unit == 0).unwrap_or(item.text.len());
            let has_buffer = fields.text != 0 && fields.count != 0;
            let copied = item_info::query_text_units(units, fields.count, has_buffer);
            if has_buffer {
                for (offset, unit) in item.text.iter().take(copied).enumerate() {
                    let Some(address) = fields.text.checked_add(offset as u64 * 2) else { return 0; };
                    if uaccess::copy_to_user(address, &unit.to_le_bytes()).is_err() { return 0; }
                }
                let Some(terminator) = fields.text.checked_add(copied as u64 * 2) else { return 0; };
                if uaccess::copy_to_user(terminator, &0u16.to_le_bytes()).is_err() { return 0; }
            }
            if !store(item_info::OFFSET_COUNT, &(copied as u32).to_le_bytes()) { return 0; }
        }
        return 1;
    }
    // A set or an insert carries its text as a NUL-terminated string at the
    // pointer field: the character count belongs to a query, and the loader
    // that appends a resource item leaves it zero.
    let text = match fields.read_text(|address| { let mut bytes = [0u8; 2]; uaccess::copy_from_user(&mut bytes, address).ok()?; Some(u16::from_le_bytes(bytes)) }) {
        Ok(text) => text,
        Err(_) => return 0,
    };
    if method == INSERT {
        let insert_position = if flags & BY_POSITION != 0 && position == u32::MAX { entries[index].menus.count(menu).ok().unwrap_or(usize::MAX) } else { position as usize };
        let item = ipc::win32_menu::MenuItem { id: fields.id_value().unwrap_or(0), state: fields.insert_flags(),
            text: text.unwrap_or_default(), submenu: fields.submenu_value().flatten() };
        if entries[index].menus.insert(menu, insert_position, item).is_err() { return 0; }
        return 1;
    }
    if method != SET { return 0; }
    let Ok(item_position) = entries[index].menus.position(menu, position, flags) else { return 0; };
    if entries[index].menus.set_item(menu, item_position, fields.id_value(), fields.type_value(), fields.state_value(), text, fields.submenu_value()).is_err() { return 0; }
    1
}
