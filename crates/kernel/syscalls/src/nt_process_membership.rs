//! Station/desktop membership selection for a newly created NT process.
//!
//! Selection operates on admitted process-local handles. A name or
//! display/session identifier is never an authority: the creation hook
//! performs namespace/security admission and passes these leases, and the
//! granted rights travel with them.
//!
//! Selection is deliberately separate from installation. Installation touches
//! a live child task and is therefore target-only; the precedence and type
//! rules decided here are the part a hosted test can actually reach.

use alloc::sync::Arc;

use sched::nt_object::{NtHandle, NtHandleTable, NtObject, NtObjectType};

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

pub(crate) fn validate_membership(
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
        let (station, _) = pair(31, 32);
        let event = NtObject::new(NtObjectType::Event, 33);
        let result = select_process_membership(ProcessDesktopCandidates {
            inherited_station: None,
            inherited_desktop: None,
            explicit_station: None,
            explicit_desktop: Some(admitted(event, 1)),
            parent_station: Some(admitted(station, 1)),
            parent_thread_desktop: None,
            parent_default_desktop: None,
        });
        assert!(matches!(result, Err(DesktopMembershipError::WrongType)));
    }

    #[test]
    fn a_missing_station_is_reported_before_any_desktop_is_examined() {
        // Selection resolves the station first, so a launch with no station at
        // all says so. Reporting the desktop's type instead would send a caller
        // looking for a desktop defect it does not have.
        let event = NtObject::new(NtObjectType::Event, 41);
        let result = select_process_membership(ProcessDesktopCandidates {
            inherited_station: None,
            inherited_desktop: None,
            explicit_station: None,
            explicit_desktop: Some(admitted(event, 1)),
            parent_station: None,
            parent_thread_desktop: None,
            parent_default_desktop: None,
        });
        assert!(matches!(result, Err(DesktopMembershipError::MissingStation)));
    }

    #[test]
    fn a_station_without_any_desktop_candidate_reports_the_missing_desktop() {
        let (station, _) = pair(51, 52);
        let result = select_process_membership(ProcessDesktopCandidates {
            inherited_station: None,
            inherited_desktop: None,
            explicit_station: None,
            explicit_desktop: None,
            parent_station: Some(admitted(station, 1)),
            parent_thread_desktop: None,
            parent_default_desktop: None,
        });
        assert!(matches!(result, Err(DesktopMembershipError::MissingDesktop)));
    }
}
