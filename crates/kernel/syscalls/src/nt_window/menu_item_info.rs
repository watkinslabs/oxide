//! The one thunked MENUITEMINFO entry point: a method word selects the
//! transaction, and every decision it makes — which slot is which, what a miss
//! answers, how far a text copy reaches, how a code page renders an item's
//! text — belongs to the ungated menu owner. This file only resolves the
//! calling process, moves bytes across the user boundary and hands the work
//! down.
use super::*;
use ipc::win32_menu::{item_info, method::MenuItemMethod, MenuManager};

/// Apply or query Wine's x86-64 MENUITEMINFO transaction against the one
/// canonical process menu owner. # C: O(N_process_gui_states + N_items)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn thunked_menu_item_info(raw: u64, position: u64, flags: u64, method: u64, info: u64) -> u64 {
    let Some(method) = MenuItemMethod::from_raw(method) else { return 0; };
    let miss = method.miss_value();
    let (Some(menu), Some(position), Some(flags)) = (u32::try_from(raw).ok().and_then(ipc::win32_menu::MenuId::from_raw), u32::try_from(position).ok(), u32::try_from(flags).ok()) else { return miss; };
    let Some(cur) = sched::live::current() else { return miss; };
    if !cur.is_nt_personality() { return miss; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return miss; };
    let menus = &mut entries[index].menus;
    match method {
        MenuItemMethod::GetMenuItemId => menus.item_id(menu, position, flags) as u64,
        MenuItemMethod::GetMenuState => menus.item_state(menu, position, flags) as u64,
        MenuItemMethod::GetSubMenu => menus.sub_menu(menu, position) as u64,
        MenuItemMethod::GetMenuDefaultItem => menus.default_item(menu, position != 0, flags) as u64,
        MenuItemMethod::CheckMenuRadioItem => check_radio_item(menus, menu, position, flags, info),
        MenuItemMethod::GetMenuItemInfoA | MenuItemMethod::GetMenuItemInfoW => query(menus, menu, position, flags, info, method.is_ansi_query()),
        MenuItemMethod::SetMenuItemInfo | MenuItemMethod::InsertMenuItem => write(menus, menu, position, flags, info, method),
    }
}

/// The radio-range caller carries its last item and its chosen item in the
/// count and mask words of an otherwise uninitialised block, so nothing else
/// in that block — the size word included — may be read.
#[cfg(target_os = "oxide-kernel")]
fn check_radio_item(menus: &mut MenuManager, menu: ipc::win32_menu::MenuId, first: u32, flags: u32, info: u64) -> u64 {
    if info == 0 { return 0; }
    let word = |offset: usize| -> Option<u32> {
        let mut bytes = [0u8; 4];
        uaccess::copy_from_user(&mut bytes, info.checked_add(offset as u64)?).ok()?;
        Some(u32::from_le_bytes(bytes))
    };
    let (Some(last), Some(check)) = (word(item_info::OFFSET_COUNT), word(item_info::OFFSET_MASK)) else { return 0; };
    menus.check_radio_item(menu, first, last, check, flags) as u64
}

/// Answer the fields one query's mask names, with its text in wide units or in
/// the caller's code page.
#[cfg(target_os = "oxide-kernel")]
fn query(menus: &MenuManager, menu: ipc::win32_menu::MenuId, position: u32, flags: u32, info: u64, ansi: bool) -> u64 {
    let mut image = [0u8; item_info::MENUITEMINFO_BYTES];
    if info == 0 || uaccess::copy_from_user(&mut image, info).is_err() { return 0; }
    let Some(fields) = item_info::ItemInfo::decode(&image) else { return 0; };
    if item_info::query_mask_conflict(fields.mask) { return 0; }
    let Ok(item) = menus.item(menu, position, flags) else { return 0; };
    let field = |offset: usize| info.checked_add(offset as u64);
    let store = |offset: usize, bytes: &[u8]| field(offset).is_some_and(|address| uaccess::copy_to_user(address, bytes).is_ok());
    if item_info::query_writes_type(fields.mask) && !store(item_info::OFFSET_TYPE, &(item.state & item_info::MENUITEMINFO_TYPE_MASK).to_le_bytes()) { return 0; }
    if fields.mask & item_info::MIIM_STATE != 0 && !store(item_info::OFFSET_STATE, &(item.state & item_info::MENUITEMINFO_STATE_MASK).to_le_bytes()) { return 0; }
    if fields.mask & item_info::MIIM_ID != 0 && !store(item_info::OFFSET_ID, &item.id.to_le_bytes()) { return 0; }
    // The reference clears the submenu field of every query that did not ask
    // for it, so a caller never reads a stale handle out of its own block.
    if !store(item_info::OFFSET_SUBMENU, &u64::from(if fields.mask & item_info::MIIM_SUBMENU != 0 { item.submenu.unwrap_or(0) } else { 0 }).to_le_bytes()) { return 0; }
    if !item_info::query_writes_text(fields.mask) { return 1; }
    let units = item.text.iter().position(|unit| *unit == 0).unwrap_or(item.text.len());
    let has_buffer = fields.text != 0 && fields.count != 0;
    let copied = if ansi {
        let bytes = ipc::win32_text::utf16_to_ansi(&item.text[..units]);
        let copied = item_info::query_text_units(bytes.len(), fields.count, has_buffer);
        if has_buffer && !store_text(fields.text, &bytes[..copied], &[0u8]) { return 0; }
        copied
    } else {
        let copied = item_info::query_text_units(units, fields.count, has_buffer);
        let mut wide = alloc::vec::Vec::new();
        for unit in item.text.iter().take(copied) { wide.extend_from_slice(&unit.to_le_bytes()); }
        if has_buffer && !store_text(fields.text, &wide, &0u16.to_le_bytes()) { return 0; }
        copied
    };
    if !store(item_info::OFFSET_COUNT, &(copied as u32).to_le_bytes()) { return 0; }
    1
}

/// Copy one query's text and the terminator that follows it.
#[cfg(target_os = "oxide-kernel")]
fn store_text(buffer: u64, body: &[u8], terminator: &[u8]) -> bool {
    if !body.is_empty() && uaccess::copy_to_user(buffer, body).is_err() { return false; }
    let Some(end) = buffer.checked_add(body.len() as u64) else { return false; };
    uaccess::copy_to_user(end, terminator).is_ok()
}

/// Insert one item or replace the fields of an existing one.
#[cfg(target_os = "oxide-kernel")]
fn write(menus: &mut MenuManager, menu: ipc::win32_menu::MenuId, position: u32, flags: u32, info: u64, method: MenuItemMethod) -> u64 {
    let mut image = [0u8; item_info::MENUITEMINFO_BYTES];
    if info == 0 || uaccess::copy_from_user(&mut image, info).is_err() { return 0; }
    let Some(fields) = item_info::ItemInfo::decode(&image) else { return 0; };
    // A set or an insert carries its text as a NUL-terminated string at the
    // pointer field: the character count belongs to a query, and the loader
    // that appends a resource item leaves it zero.
    let Ok(text) = fields.read_text(|address| { let mut bytes = [0u8; 2]; uaccess::copy_from_user(&mut bytes, address).ok()?; Some(u16::from_le_bytes(bytes)) }) else { return 0; };
    if method == MenuItemMethod::InsertMenuItem {
        let insert_position = if flags & ipc::win32_menu::MF_BYPOSITION != 0 && position == u32::MAX { menus.count(menu).ok().unwrap_or(usize::MAX) } else { position as usize };
        let item = ipc::win32_menu::MenuItem { id: fields.id_value().unwrap_or(0), state: fields.insert_flags(),
            text: text.unwrap_or_default(), submenu: fields.submenu_value().flatten() };
        return menus.insert(menu, insert_position, item).is_ok() as u64;
    }
    let Ok(item_position) = menus.position(menu, position, flags) else { return 0; };
    menus.set_item(menu, item_position, fields.id_value(), fields.type_value(), fields.state_value(), text, fields.submenu_value()).is_ok() as u64
}
