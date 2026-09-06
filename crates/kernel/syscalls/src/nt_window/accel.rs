//! Per-process accelerator tables and the translate decision's window facts.
use super::*;
use crate::nt_wine_window::accel_raw::{MenuPlacement, Target};
use ipc::win32_accel::{Accel, AccelError};

fn with_entry<T>(f: impl FnOnce(&mut GuiEntry) -> T) -> Option<T> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| { entries.push(new_entry(&group)); entries.len() - 1 });
    Some(f(&mut entries[index]))
}

/// # C: O(processes + entries)
pub(crate) fn accel_create_for_current(entries: &[Accel]) -> Result<u32, AccelError> {
    with_entry(|entry| entry.accelerators.create(entries)).unwrap_or(Err(AccelError::NoMemory))
}
/// # C: O(processes + entries)
pub(crate) fn accel_copy_for_current(handle: u32, limit: usize) -> Result<Vec<Accel>, AccelError> {
    with_entry(|entry| entry.accelerators.copy(handle, limit)).unwrap_or(Err(AccelError::NoSuchTable))
}
/// # C: O(processes + tables)
pub(crate) fn accel_destroy_for_current(handle: u32) -> Result<(), AccelError> {
    with_entry(|entry| entry.accelerators.destroy(handle)).unwrap_or(Err(AccelError::NoSuchTable))
}

fn locate(menus: &ipc::win32_menu::MenuManager, bar: Option<u32>, cmd: u32) -> Option<(MenuPlacement, u32)> {
    let bar_id = ipc::win32_menu::MenuId::from_raw(bar?)?;
    if let Ok(item) = menus.item(bar_id, cmd, 0) { return Some((MenuPlacement::InBar, item.state)); }
    let count = menus.count(bar_id).ok()?;
    for position in 0..count {
        let Ok(top) = menus.item(bar_id, position as u32, ipc::win32_menu::MF_BYPOSITION) else { continue; };
        let Some(sub) = top.submenu.and_then(ipc::win32_menu::MenuId::from_raw) else { continue; };
        if let Ok(item) = menus.item(sub, cmd, 0) { return Some((MenuPlacement::InPopup { submenu: sub.raw(), position: position as u32 }, item.state)); }
    }
    None
}

/// Window style, capture and the command's menu placement for the send plan.
/// # C: O(processes + windows + menu items)
pub(crate) fn accel_target_for_current(hwnd: u64, cmd: u16) -> Option<Target> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let id = valid_window(hwnd)?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    let record = entry.state.get(id)?;
    let (placement, item_state) = locate(&entry.menus, record.menu, u32::from(cmd)).unwrap_or((MenuPlacement::NotInMenu, 0));
    Some(Target { style: record.style, captured: entry.state.captured().is_some(), menu: record.menu.unwrap_or(0), placement, item_state })
}
