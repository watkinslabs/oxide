//! Window tree access for the calling process. Every walk lives in the window
//! owner; this module resolves the caller and converts handles.
use super::super::*;
use alloc::vec::Vec;
use ipc::win32_window::{HwndListFilter, WindowError, WindowId};

fn id(hwnd: u64) -> Option<WindowId> { valid_window(hwnd) }

fn raw(window: Option<WindowId>) -> u64 { window.map_or(0, |window| window.raw() as u64) }

/// GetAncestor for the calling process. # C: O(N_processes + N_windows²)
pub(crate) fn ancestor_for_current(hwnd: u64, kind: u32) -> u64 {
    let Some(window) = id(hwnd) else { return 0; };
    raw(access::with_state(|state| state.ancestor(window, kind)).flatten())
}

/// ChildWindowFromPointEx. # C: O(N_processes + N_windows²)
pub(crate) fn child_from_point_for_current(parent: u64, x: i32, y: i32, flags: u32) -> u64 {
    let Some(parent) = id(parent) else { return 0; };
    raw(access::with_state(|state| state.child_from_point(parent, x, y, flags)).flatten())
}

/// WindowFromPoint, with its hit-test answer. # C: O(N_processes + N_windows²)
pub(crate) fn window_from_point_for_current(x: i32, y: i32) -> (u64, i32) {
    let found = access::with_state(|state| state.window_from_point(None, x, y));
    let (window, hittest) = found.unwrap_or((None, ipc::win32_window::HTNOWHERE));
    (raw(window), hittest)
}

/// FindWindowEx, resolving the class name to its atom first. A class name that
/// names no registered class matches nothing. # C: O(N_processes + N_windows²)
pub(crate) fn find_window_for_current(parent: u64, after: u64, class: Option<&[u16]>, title: Option<&[u16]>) -> u64 {
    let parent = (parent != 0).then(|| id(parent)).flatten();
    let after = (after != 0).then(|| id(after)).flatten();
    raw(access::with_state(|state| {
        let atom = match class {
            None => 0,
            Some(name) => match state.class_info(name) { Some((atom, _, _)) => atom, None => return None },
        };
        state.find_child(parent, after, atom, title)
    }).flatten())
}

/// Build one handle list. # C: O(N_processes + N_windows²)
pub(crate) fn hwnd_list_for_current(filter: HwndListFilter) -> Vec<u32> {
    access::with_state(|state| state.hwnd_list(filter).iter().map(|id| id.raw()).collect()).unwrap_or_default()
}

/// One window's text, without entering its window procedure. # C: O(N_processes + N_windows + N_text)
pub(crate) fn internal_window_text_for_current(hwnd: u64, out: &mut Vec<u16>) -> Option<()> {
    let window = id(hwnd)?;
    access::with_state(|state| {
        let text = state.text(window)?;
        out.try_reserve_exact(text.len()).ok()?;
        out.extend_from_slice(text);
        Some(())
    })?
}

/// SetParent, answering the parent the window left. # C: O(N_processes + N_windows²)
pub(crate) fn set_parent_for_current(hwnd: u64, parent: u64) -> Result<u64, WindowError> {
    let window = id(hwnd).ok_or(WindowError::NoSuchWindow)?;
    let parent = if parent == 0 { None } else { Some(id(parent).ok_or(WindowError::InvalidParent)?) };
    let tid = sched::live::current().map_or(0, |task| task.tid as u64);
    let old=access::with_state_mut(|state| state.set_parent(tid, window, parent))
        .unwrap_or(Err(WindowError::NoSuchWindow))?;
    if old!=parent{bridge::publish_reparent_current(hwnd).map_err(|_|WindowError::InvalidParameter)?;}
    Ok(raw(old))
}

/// Window one device context draws into. # C: O(N_processes + N_dcs)
pub(crate) fn window_from_dc_for_current(dc: u64) -> u64 {
    let Ok(dc) = u32::try_from(dc) else { return 0; };
    crate::nt_gdi::lease_window_for_current(dc).unwrap_or(0) as u64
}

/// The owned popups a show or hide request must reach, from the top of the
/// z-order down. # C: O(N_processes + N_windows²)
pub(crate) fn owned_popups_for_current(owner: u64, show: bool) -> Vec<u32> {
    let Some(owner) = id(owner) else { return Vec::new(); };
    access::with_state(|state| {
        state.siblings_top_first(None).into_iter().filter(|candidate| {
            if state.window_relative(*candidate, ipc::win32_window::styles::GW_OWNER) != Some(owner) { return false; }
            let Some(record) = state.get(*candidate) else { return false };
            // Showing reaches every owned popup; hiding reaches the visible ones.
            show || record.style & ipc::win32_window::styles::WS_VISIBLE != 0
        }).map(|id| id.raw()).collect()
    }).unwrap_or_default()
}

/// The minimized children an arrange request repositions, in sibling order.
/// # C: O(N_processes + N_windows²)
pub(crate) fn iconic_children_for_current(parent: u64) -> Vec<u32> {
    let parent = (parent != 0).then(|| id(parent)).flatten();
    access::with_state(|state| {
        let mut children = state.siblings_top_first(parent);
        children.reverse();
        children.into_iter()
            .filter(|child| state.get(*child).is_some_and(|record| record.style & ipc::win32_window::styles::WS_MINIMIZE != 0))
            .map(|id| id.raw()).collect()
    }).unwrap_or_default()
}

/// Properties one window carries, as value, atom and whether the atom came
/// from a string. # C: O(N_processes + N_windows + N_properties)
pub(crate) fn property_list_for_current(hwnd: u64) -> Option<Vec<(u64, u16, bool)>> {
    let window = id(hwnd)?;
    access::with_state(|state| state.property_list(window))?
}
