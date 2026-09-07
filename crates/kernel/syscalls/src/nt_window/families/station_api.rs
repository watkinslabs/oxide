//! Window-station and desktop membership access. The NT object namespace and
//! the thread's canonical membership own the state; this module resolves the
//! caller and the desktop-wide input selection.
use super::super::*;
use alloc::{string::String, vec::Vec};
use sched::nt_object::{namespace, NtHandle, NtObject, NtObjectType};

/// The desktop input currently reaches. It is desktop-wide, like the input
/// itself, and a switch names a different one.
static INPUT_DESKTOP: Spinlock<Option<Arc<NtObject>>, GuiLockClass> = Spinlock::new(None);
/// Flags carried per object by the information calls, keyed by object identity.
static OBJECT_FLAGS: Spinlock<Vec<(u64, u32)>, GuiLockClass> = Spinlock::new(Vec::new());

/// Station the calling process belongs to. # C: O(1)
pub(crate) fn process_station() -> Option<Arc<NtObject>> {
    let task = sched::live::current().filter(|task| task.is_nt_personality())?;
    let station = task.thread_group.nt_window_station.lock().clone();
    station
}

/// Open one object in the calling process's handle table. # C: O(N_handles)
pub(crate) fn open_handle(object: Arc<NtObject>, access: u32) -> u64 {
    let Some(task) = sched::live::current().filter(|task| task.is_nt_personality()) else { return 0; };
    task.thread_group.nt_handles().insert(object, access).map_or(0, |handle| handle.raw() as u64)
}

/// Resolve one handle to its object. # C: O(N_handles)
pub(crate) fn object_by_handle(handle: NtHandle) -> Option<Arc<NtObject>> {
    let task = sched::live::current().filter(|task| task.is_nt_personality())?;
    let object = task.thread_group.nt_handles().get(handle, 0);
    object
}

/// Whether one handle is still open in the calling process. # C: O(N_handles)
pub(crate) fn handle_inherits(handle: NtHandle) -> bool {
    sched::live::current().filter(|task| task.is_nt_personality())
        .is_some_and(|task| task.thread_group.nt_handles().access(handle).is_some())
}

/// Close one handle. # C: O(N_handles)
pub(crate) fn close_handle(handle: NtHandle) -> bool {
    sched::live::current().filter(|task| task.is_nt_personality())
        .is_some_and(|task| task.thread_group.nt_handles().close(handle))
}

/// Create or reopen one named window station. # C: O(namespace + path)
pub(crate) fn create_station(path: &str) -> Option<Arc<NtObject>> {
    namespace::create_window_station(path).ok().map(|(object, _)| object)
}

/// Open one existing named window station. # C: O(namespace + path)
pub(crate) fn open_station(path: &str) -> Option<Arc<NtObject>> {
    namespace::lookup_object(path, NtObjectType::WindowStation)
}

/// Create or reopen one named desktop below a station. # C: O(namespace + path)
pub(crate) fn create_desktop_object(path: &str, station: Arc<NtObject>) -> Option<Arc<NtObject>> {
    namespace::create_desktop(path, station).ok().map(|(object, _)| object)
}

/// Open one existing named desktop. # C: O(namespace + path)
pub(crate) fn open_desktop_object(path: &str) -> Option<Arc<NtObject>> {
    namespace::lookup_object(path, NtObjectType::Desktop)
}

/// Directory and leaf name one object is published under. # C: O(namespace)
pub(crate) fn object_location(object: &Arc<NtObject>) -> Option<(String, String)> {
    Some((namespace::directory_path(object)?, namespace::object_name(object)?))
}

/// A handle onto the process station, opened in the caller's table.
/// # C: O(N_handles)
pub(crate) fn process_station_handle() -> u64 {
    let Some(station) = process_station() else { return 0; };
    open_handle(station, crate::nt_desktop_names::STATION_ACCESS)
}

/// Move the calling process onto another station. # C: O(N_handles)
pub(crate) fn set_process_station(handle: NtHandle) -> bool {
    let Some(task) = sched::live::current().filter(|task| task.is_nt_personality()) else { return false; };
    let Some(station) = object_by_handle(handle) else { return false; };
    if station.kind() != NtObjectType::WindowStation { return false; }
    *task.thread_group.nt_window_station.lock() = Some(station);
    true
}

/// A handle onto one thread's desktop; a thread of zero is the caller.
/// # C: O(N_tasks + N_handles)
pub(crate) fn thread_desktop_handle(thread: u32) -> u64 {
    let desktop = if thread == 0 {
        sched::live::current().filter(|task| task.is_nt_personality()).and_then(|task| task.nt_desktop.lock().object())
    } else {
        sched::registry::lookup(thread).filter(|task| task.is_nt_personality())
            .and_then(|task| task.nt_desktop.lock().object())
    };
    let Some(desktop) = desktop else { return 0; };
    open_handle(desktop, crate::nt_desktop_names::DESKTOP_ACCESS)
}

/// Attach the calling thread to another desktop of its own station.
/// # C: O(N_handles)
pub(crate) fn set_thread_desktop(handle: NtHandle) -> bool {
    let (Some(task), Some(station)) = (sched::live::current().filter(|task| task.is_nt_personality()),
        process_station()) else { return false; };
    let Some(desktop) = object_by_handle(handle) else { return false; };
    let selected = task.nt_desktop.lock().select(&station, desktop, false).is_ok();
    selected
}

/// Make one desktop the one input reaches. # C: O(N_handles)
pub(crate) fn switch_desktop(handle: NtHandle) -> bool {
    let Some(desktop) = object_by_handle(handle) else { return false; };
    if desktop.kind() != NtObjectType::Desktop { return false; }
    *INPUT_DESKTOP.lock() = Some(desktop);
    true
}

/// The desktop input currently reaches, defaulting to the calling thread's own
/// before any switch has happened. # C: O(1)
pub(crate) fn input_desktop() -> Option<Arc<NtObject>> {
    if let Some(desktop) = INPUT_DESKTOP.lock().clone() { return Some(desktop); }
    let task = sched::live::current().filter(|task| task.is_nt_personality())?;
    let desktop = task.nt_desktop.lock().object();
    desktop
}

/// Flags one object carries; an object that never had any carries none.
/// # C: O(N_objects)
pub(crate) fn object_flags(object: &Arc<NtObject>) -> u32 {
    OBJECT_FLAGS.lock().iter().find(|(id, _)| *id == object.id()).map_or(0, |(_, flags)| *flags)
}

/// Record the flags one object carries. # C: O(N_objects)
pub(crate) fn set_object_flags(object: &Arc<NtObject>, flags: u32) -> bool {
    let mut recorded = OBJECT_FLAGS.lock();
    if let Some(entry) = recorded.iter_mut().find(|(id, _)| *id == object.id()) { entry.1 = flags; return true; }
    if recorded.try_reserve(1).is_err() { return false; }
    recorded.push((object.id(), flags));
    true
}

/// Names one station holds, or the station names when no station is given.
/// # C: O(namespace entries)
pub(crate) fn station_entry_names(handle: NtHandle) -> Vec<String> {
    let station = if handle.raw() == 0 { process_station() } else { object_by_handle(handle) };
    let Some(station) = station.filter(|object| object.kind() == NtObjectType::WindowStation) else { return Vec::new(); };
    namespace::directory_entries(&station).into_iter().map(|(name, _)| name).collect()
}
