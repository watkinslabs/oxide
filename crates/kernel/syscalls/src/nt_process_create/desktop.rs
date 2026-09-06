//! Installation of selected station/desktop membership into a fresh child.
//!
//! Selection and its rules live in `nt_process_membership`, which a hosted
//! test can reach; this module only mutates a live child task.

#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

use alloc::sync::Arc;

use sched::nt_object::ThreadDesktop;
use crate::nt_process_membership::{DesktopMembershipError, ProcessDesktopMembership, validate_membership};

/// Install selected membership into an unpublished child. Handles are inserted
/// before membership mutation; failure closes admitted child handles and leaves
/// membership untouched.
pub(crate) fn attach_process_membership(
    child: &sched::Task,
    membership: &ProcessDesktopMembership,
) -> Result<(), DesktopMembershipError> {
    validate_membership(&membership.station.object, &membership.desktop.object)?;
    let table = &child.thread_group.nt_handles;
    let station_handle = table.insert(Arc::clone(&membership.station.object), membership.station.access)
        .ok_or(DesktopMembershipError::NoChildHandle)?;
    let Some(desktop_handle) = table.insert(Arc::clone(&membership.desktop.object), membership.desktop.access) else {
        let _ = table.close(station_handle);
        return Err(DesktopMembershipError::NoChildHandle);
    };
    let rollback = || {
        let _ = table.close(station_handle);
        let _ = table.close(desktop_handle);
    };

    if let Some(old) = child.thread_group.nt_window_station.lock().clone() {
        if !Arc::ptr_eq(&old, &membership.station.object) {
            rollback();
            return Err(DesktopMembershipError::ConflictingStation);
        }
    }
    if let Some(old) = child.thread_group.nt_default_desktop.lock().object() {
        if !Arc::ptr_eq(&old, &membership.desktop.object) {
            rollback();
            return Err(DesktopMembershipError::ConflictingDesktop);
        }
    }
    if let Some(old) = child.nt_desktop.lock().object() {
        if !Arc::ptr_eq(&old, &membership.desktop.object) {
            rollback();
            return Err(DesktopMembershipError::ConflictingDesktop);
        }
    }

    let mut selected = ThreadDesktop::default();
    if selected.select(&membership.station.object, Arc::clone(&membership.desktop.object), false).is_err() {
        rollback();
        return Err(DesktopMembershipError::WrongStation);
    }
    *child.thread_group.nt_window_station.lock() = Some(Arc::clone(&membership.station.object));
    child.thread_group.nt_default_desktop.lock().inherit_default(&selected);
    child.nt_desktop.lock().inherit_default(&selected);
    Ok(())
}

