//! Trusted native-process desktop attachment preparation using canonical NT handles.
use alloc::{string::String, sync::Arc};
use super::super::{namespace, NtHandle, NtHandleTable, NtObject, NamedObjectState};
use super::{DesktopError, ThreadDesktop};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesktopBootstrapError { Namespace(namespace::DesktopPublishError), TypeCollision, InvalidName, NoMemory, NoHandles }

/// Handles remain table-owned after commit; dropping uncommitted preparation closes them.
pub struct DesktopBootstrap<'a> {
    table: &'a NtHandleTable,
    pub station: Arc<NtObject>, pub desktop: Arc<NtObject>,
    pub station_handle: NtHandle, pub desktop_handle: NtHandle,
    committed: bool,
}
impl DesktopBootstrap<'_> {
    /// Bootstrap defaults never replace prior thread membership. # C: O(1)
    pub fn attach(&self, thread: &mut ThreadDesktop) -> Result<(), DesktopError> {
        if let Some(old) = thread.object() {
            return if Arc::ptr_eq(&old, &self.desktop) { Ok(()) } else { Err(DesktopError::Busy) };
        }
        thread.select(&self.station, self.desktop.clone(), false)
    }
    /// Transfer admitted handle lifetime to the process table after storing canonical membership. # C: O(1)
    pub fn commit(mut self) { self.committed = true; }
}
impl Drop for DesktopBootstrap<'_> {
    fn drop(&mut self) {
        if !self.committed { self.table.close(self.desktop_handle); self.table.close(self.station_handle); }
    }
}

/// Caller authorizes namespace parent and rights before entry; no session/desktop guessing.
/// No GUI or caller handle-table lock may be held. # C: O(namespace + handles + path)
pub fn bootstrap_desktop<'a>(table: &'a NtHandleTable, station_path: &str, desktop_name: &str,
    station_access: u32, desktop_access: u32) -> Result<DesktopBootstrap<'a>, DesktopBootstrapError> {
    if desktop_name.is_empty() || desktop_name == "." || desktop_name == ".."
        || desktop_name.contains(['\\','/','\0']) { return Err(DesktopBootstrapError::InvalidName); }
    let length = station_path.len().checked_add(1).and_then(|n| n.checked_add(desktop_name.len())).ok_or(DesktopBootstrapError::NoMemory)?;
    let mut path=String::new();path.try_reserve_exact(length).map_err(|_| DesktopBootstrapError::NoMemory)?;
    path.push_str(station_path);path.push('\\');path.push_str(desktop_name);
    let (station,state)=namespace::create_window_station(station_path).map_err(DesktopBootstrapError::Namespace)?;
    if state==NamedObjectState::TypeMismatch { return Err(DesktopBootstrapError::TypeCollision); }
    let station_handle=match table.insert(station.clone(),station_access) {
        Some(handle)=>handle,
        None=>{namespace::release_temporary(&station,false);return Err(DesktopBootstrapError::NoHandles);}
    };
    let prepared=(|| {
        let (desktop,state)=namespace::create_desktop(&path,station.clone()).map_err(DesktopBootstrapError::Namespace)?;
        if state==NamedObjectState::TypeMismatch { return Err(DesktopBootstrapError::TypeCollision); }
        let desktop_handle=match table.insert(desktop.clone(),desktop_access) {
            Some(handle)=>handle,
            None=>{namespace::release_temporary(&desktop,false);return Err(DesktopBootstrapError::NoHandles);}
        };
        Ok((desktop,desktop_handle))
    })();
    match prepared {
        Ok((desktop,desktop_handle))=>Ok(DesktopBootstrap {table,station,desktop,station_handle,desktop_handle,committed:false}),
        Err(error)=>{table.close(station_handle);Err(error)}
    }
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod tests;
