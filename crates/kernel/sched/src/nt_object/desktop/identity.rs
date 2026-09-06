//! Canonical selected identity; names and display transport never grant membership.
use alloc::sync::Arc;
use super::{DesktopError, ThreadDesktop};
use super::super::{NtHandle, NtHandleTable, NtObject, NtObjectType};

impl ThreadDesktop {
    /// Resolve membership without requiring a published root. # C: O(1)
    pub fn identity(&self, station: &Arc<NtObject>) -> Result<Arc<NtObject>, DesktopError> {
        if station.kind() != NtObjectType::WindowStation { return Err(DesktopError::WrongType); }
        let object = self.object().ok_or(DesktopError::NotAttached)?;
        let payload = object.desktop().ok_or(DesktopError::WrongType)?;
        if !Arc::ptr_eq(&payload.station(), station) { return Err(DesktopError::WrongStation); }
        Ok(object)
    }

    /// Operates on a detached membership snapshot; caller holds no Task/GUI lock during lookup.
    /// Handle admission already owns granted rights; selection creates no new handle. # C: O(1)
    pub fn select_handle(&mut self, table: &NtHandleTable, station: &Arc<NtObject>,
        handle: NtHandle, has_users: bool) -> Result<(), DesktopError> {
        if station.kind() != NtObjectType::WindowStation { return Err(DesktopError::WrongType); }
        let desktop = table.get(handle, 0).ok_or(DesktopError::NotAttached)?;
        self.select(station, desktop, has_users)
    }
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
