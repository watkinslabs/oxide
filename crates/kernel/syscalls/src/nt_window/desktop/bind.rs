//! Initial-thread desktop binding consumes existing canonical handles, never names.
use alloc::sync::Arc;
use sched::nt_object::{NtHandle, NtObjectType, ThreadDesktop};

const SUCCESS: u64 = 0;
const INVALID_PARAMETER: u64 = 0xc000_000d;
const INVALID_HANDLE: u64 = 0xc000_0008;
const OBJECT_TYPE_MISMATCH: u64 = 0xc000_0024;
const ACCESS_DENIED: u64 = 0xc000_0022;
const DEVICE_BUSY: u64 = 0x8000_0011;

/// Tagged bootstrap hook, callable before NT activation. No caller lock may be held.
/// Caller supplies already-issued handles; this service does not issue session authority.
/// # C: O(1); # Sleeps: no
pub(crate) fn bind_for_current(station_handle: u64, desktop_handle: u64) -> u64 {
    let (Ok(station_handle), Ok(desktop_handle)) = (u32::try_from(station_handle), u32::try_from(desktop_handle))
        else { return INVALID_PARAMETER; };
    let Some(current) = sched::live::current() else { return INVALID_PARAMETER; };
    let table = &current.thread_group.nt_handles;
    let Some(station) = table.get(NtHandle::from_raw(station_handle), 0) else { return INVALID_HANDLE; };
    if station.kind() != NtObjectType::WindowStation { return OBJECT_TYPE_MISMATCH; }
    let Some(desktop) = table.get(NtHandle::from_raw(desktop_handle), 0) else { return INVALID_HANDLE; };
    let Some(payload) = desktop.desktop() else { return OBJECT_TYPE_MISMATCH; };
    if !Arc::ptr_eq(&payload.station(), &station) { return ACCESS_DENIED; }
    // Only the sole initial thread can publish membership; no peer can race these separate locks.
    if current.thread_group.live_count() != 1 { return DEVICE_BUSY; }
    let old_station = current.thread_group.nt_window_station.lock().clone();
    if old_station.as_ref().is_some_and(|old| !Arc::ptr_eq(old, &station)) { return DEVICE_BUSY; }
    let old_desktop = current.nt_desktop.lock().object();
    if old_desktop.as_ref().is_some_and(|old| !Arc::ptr_eq(old, &desktop)) { return DEVICE_BUSY; }
    let old_default = current.thread_group.nt_default_desktop.lock().object();
    if old_default.as_ref().is_some_and(|old| !Arc::ptr_eq(old, &desktop)) { return DEVICE_BUSY; }
    if old_desktop.is_none() {
        let entries = super::GUI.lock();
        if entries.iter().any(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group)) && entry.state.len() != 0) {
            return DEVICE_BUSY;
        }
    }
    let mut selected = ThreadDesktop::default();
    if selected.select(&station, desktop, false).is_err() { return ACCESS_DENIED; }
    *current.thread_group.nt_window_station.lock() = Some(station);
    current.thread_group.nt_default_desktop.lock().inherit_default(&selected);
    *current.nt_desktop.lock() = selected;
    SUCCESS
}
