//! Per-process accelerator tables and the translate decision's window facts.
use super::*;
use crate::nt_wine_window::accel_raw::{locate, MenuOwner, MenuPlacement, Target};
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

/// Window style, capture and the command's menu placement for the send plan.
/// The window's system menu is searched ahead of its own menu, the way the
/// reference resolves a command that both could carry.
/// # C: O(processes + windows + menu items)
pub(crate) fn accel_target_for_current(hwnd: u64, cmd: u16) -> Option<Target> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let id = valid_window(hwnd)?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    let record = entry.state.get(id)?;
    // A child owns a control identifier in the shared slot, not a menu, so it
    // never names a command position in the menu owner.
    let menu = ipc::win32_window::menu_of(record.style, record.id_menu);
    let (placement, item_state) = locate(&entry.menus, record.sys_menu, u32::from(cmd), MenuOwner::System)
        .or_else(|| locate(&entry.menus, menu, u32::from(cmd), MenuOwner::Client))
        .unwrap_or((MenuPlacement::NotInMenu, 0));
    Some(Target { style: record.style, captured: entry.state.captured().is_some(), menu: menu.unwrap_or(0),
        sys_menu: record.sys_menu.unwrap_or(0), placement, item_state })
}
