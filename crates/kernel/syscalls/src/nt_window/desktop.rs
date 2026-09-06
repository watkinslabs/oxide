//! Desktop-root resolution through canonical thread membership and GUI ownership.
use alloc::sync::Arc;
use ipc::win32_window::{WindowId, DcLeaseContext};
use sched::nt_object::NtObject;
use sched::thread_group::ThreadGroup;
use super::GUI;

#[path = "desktop/bootstrap.rs"]
mod bootstrap;
pub(crate) use bootstrap::{prepare_bound_for_current, BoundDesktop, BootstrapError};
#[path = "desktop/bind.rs"]
mod bind;
pub(crate) use bind::bind_for_current;

pub(crate) struct DesktopWindow { pub group: Arc<ThreadGroup>, pub window: WindowId }

/// Called for HWND zero; never substitutes the caller's process-local HWND namespace.
/// # C: O(processes + windows); # Sleeps: no
pub(crate) fn resolve_for_current() -> Option<DesktopWindow> {
    let current = sched::live::current().filter(|task| task.is_nt_personality())?;
    let station = current.thread_group.nt_window_station.lock().clone()?;
    let membership = current.nt_desktop.lock().clone();
    let (group, hwnd) = membership.resolve_root(&station).ok()?;
    let window = WindowId::from_raw(hwnd)?;
    {
        let entries = GUI.lock();
        let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&group)))?;
        entry.state.get(window)?;
    }
    Some(DesktopWindow { group, window })
}

/// Bootstrap publishes only after the real GUI root exists; no synthetic geometry or window record.
/// # C: O(processes + windows); # Sleeps: no
pub(crate) fn publish_root(desktop: &NtObject, group: &Arc<ThreadGroup>, hwnd: u32) -> bool {
    let Some(window) = WindowId::from_raw(hwnd) else { return false; };
    let Some(desktop) = desktop.desktop() else { return false; };
    desktop.publish_root_checked(group, hwnd, || {
        let entries = GUI.lock();
        let Some(entry) = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(group))) else { return false; };
        let Some(record) = entry.state.get(window) else { return false; };
        record.parent.is_none() && entry.state.rect(window).is_some()
    }).is_ok()
}

/// GDI must use the returned root process for its object/backing lookup and lease lifetime.
/// # C: O(processes + windows² + regions²); # Sleeps: no
pub(crate) fn dc_context_for_current(flags: u32) -> Option<(Arc<ThreadGroup>, DcLeaseContext)> {
    let target = resolve_for_current()?;
    let context = {
        let entries = GUI.lock();
        let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&target.group)))?;
        entry.state.dc_lease_context(target.window, flags).ok()?
    };
    Some((target.group, context))
}
