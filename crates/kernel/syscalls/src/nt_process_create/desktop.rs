//! Canonical station/desktop membership for a newly created NT process.
//!
//! This child module operates on admitted process-local handles. A name or
//! display/session identifier is never an authority. The parent creation
//! hook must perform namespace/security admission and then pass these leases;
//! this module preserves their granted rights when installing the fresh
//! child's process-local handles.

use alloc::sync::Arc;

use sched::nt_object::{NtHandle, NtHandleTable, NtObject, NtObjectType, ThreadDesktop};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DesktopMembershipError {
    MissingStation,
    MissingDesktop,
    WrongType,
    WrongStation,
    ConflictingStation,
    ConflictingDesktop,
    InvalidHandle,
    NoChildHandle,
}

/// One source-table admission. The Arc retains object lifetime while the
/// access mask preserves the rights granted by the source handle.
#[derive(Clone)]
pub(crate) struct AdmittedHandle {
    pub(crate) object: Arc<NtObject>,
    pub(crate) access: u32,
}

impl AdmittedHandle {
    /// Admit an existing source-table handle without widening its rights.
    pub(crate) fn from_table(table: &NtHandleTable, handle: NtHandle) -> Result<Self, DesktopMembershipError> {
        let object = table.get(handle, 0).ok_or(DesktopMembershipError::InvalidHandle)?;
        let access = table.access(handle).ok_or(DesktopMembershipError::InvalidHandle)?;
        Ok(Self { object, access })
    }
}

/// Independent candidates are required because station and desktop inherited
/// handles are selected independently by the native creation transaction.
pub(crate) struct ProcessDesktopCandidates {
    pub(crate) inherited_station: Option<AdmittedHandle>,
    pub(crate) inherited_desktop: Option<AdmittedHandle>,
    pub(crate) explicit_station: Option<AdmittedHandle>,
    pub(crate) explicit_desktop: Option<AdmittedHandle>,
    pub(crate) parent_station: Option<AdmittedHandle>,
    pub(crate) parent_thread_desktop: Option<AdmittedHandle>,
    pub(crate) parent_default_desktop: Option<AdmittedHandle>,
}

/// Selected canonical refs and their source rights, ready for child-table
/// installation. It cannot be constructed from bare Arcs at the creation
/// boundary.
pub(crate) struct ProcessDesktopMembership {
    pub(crate) station: AdmittedHandle,
    pub(crate) desktop: AdmittedHandle,
}

/// Apply the complete selection precedence without mutating the child:
/// inherited station, explicit station, then parent station; and inherited
/// desktop, explicit desktop, parent-thread desktop, then process default.
pub(crate) fn select_process_membership(
    candidates: ProcessDesktopCandidates,
) -> Result<ProcessDesktopMembership, DesktopMembershipError> {
    let station = candidates.inherited_station
        .or(candidates.explicit_station)
        .or(candidates.parent_station)
        .ok_or(DesktopMembershipError::MissingStation)?;
    let desktop = candidates.inherited_desktop
        .or(candidates.explicit_desktop)
        .or(candidates.parent_thread_desktop)
        .or(candidates.parent_default_desktop)
        .ok_or(DesktopMembershipError::MissingDesktop)?;
    validate_membership(&station.object, &desktop.object)?;
    Ok(ProcessDesktopMembership { station, desktop })
}

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

fn validate_membership(
    station: &Arc<NtObject>,
    desktop: &Arc<NtObject>,
) -> Result<(), DesktopMembershipError> {
    if station.kind() != NtObjectType::WindowStation {
        return Err(DesktopMembershipError::WrongType);
    }
    let payload = desktop.desktop().ok_or(DesktopMembershipError::WrongType)?;
    if !Arc::ptr_eq(station, &payload.station()) {
        return Err(DesktopMembershipError::WrongStation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(station_id: u64, desktop_id: u64) -> (Arc<NtObject>, Arc<NtObject>) {
        let station = NtObject::new(NtObjectType::WindowStation, station_id);
        let desktop = NtObject::new_desktop(desktop_id, Arc::clone(&station)).unwrap();
        (station, desktop)
    }

    fn admitted(object: Arc<NtObject>, access: u32) -> AdmittedHandle {
        AdmittedHandle { object, access }
    }

    #[test]
    fn inherited_handles_precede_explicit_and_parent_candidates() {
        let (inherited_station, inherited_desktop) = pair(1, 2);
        let (explicit_station, explicit_desktop) = pair(3, 4);
        let (parent_station, parent_desktop) = pair(5, 6);
        let selected = select_process_membership(ProcessDesktopCandidates {
            inherited_station: Some(admitted(Arc::clone(&inherited_station), 0x11)),
            inherited_desktop: Some(admitted(Arc::clone(&inherited_desktop), 0x22)),
            explicit_station: Some(admitted(explicit_station, 0x33)),
            explicit_desktop: Some(admitted(explicit_desktop, 0x44)),
            parent_station: Some(admitted(parent_station, 0x55)),
            parent_thread_desktop: None,
            parent_default_desktop: Some(admitted(parent_desktop, 0x66)),
        }).unwrap();
        assert!(Arc::ptr_eq(&selected.station.object, &inherited_station));
        assert!(Arc::ptr_eq(&selected.desktop.object, &inherited_desktop));
        assert_eq!(selected.station.access, 0x11);
        assert_eq!(selected.desktop.access, 0x22);
    }

    #[test]
    fn desktop_fallback_prefers_parent_thread_over_process_default() {
        let (station, thread_desktop) = pair(11, 12);
        let (_, default_desktop) = pair(11, 13);
        let selected = select_process_membership(ProcessDesktopCandidates {
            inherited_station: None,
            inherited_desktop: None,
            explicit_station: None,
            explicit_desktop: None,
            parent_station: Some(admitted(Arc::clone(&station), 1)),
            parent_thread_desktop: Some(admitted(Arc::clone(&thread_desktop), 2)),
            parent_default_desktop: Some(admitted(default_desktop, 3)),
        }).unwrap();
        assert!(Arc::ptr_eq(&selected.desktop.object, &thread_desktop));
        assert_eq!(selected.desktop.access, 2);
    }

    #[test]
    fn station_mismatch_is_rejected_without_bare_arc_authority() {
        let (station, desktop) = pair(21, 22);
        let foreign = NtObject::new(NtObjectType::WindowStation, 23);
        let result = select_process_membership(ProcessDesktopCandidates {
            inherited_station: None,
            inherited_desktop: None,
            explicit_station: None,
            explicit_desktop: None,
            parent_station: Some(admitted(foreign, 1)),
            parent_thread_desktop: None,
            parent_default_desktop: Some(admitted(desktop, 2)),
        });
        assert!(matches!(result, Err(DesktopMembershipError::WrongStation)));
        assert_eq!(station.kind(), NtObjectType::WindowStation);
    }

    #[test]
    fn wrong_explicit_object_is_rejected_without_arc_result_comparison() {
        let event = NtObject::new(NtObjectType::Event, 31);
        let result = select_process_membership(ProcessDesktopCandidates {
            inherited_station: None,
            inherited_desktop: None,
            explicit_station: None,
            explicit_desktop: Some(admitted(event, 1)),
            parent_station: None,
            parent_thread_desktop: None,
            parent_default_desktop: None,
        });
        assert!(matches!(result, Err(DesktopMembershipError::WrongType)));
    }
}
