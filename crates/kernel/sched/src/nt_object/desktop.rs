//! Canonical desktop payload and thread membership; no auxiliary namespace.
use alloc::sync::Arc;
use core::num::NonZeroU32;
use sync::{Spinlock, TaskList as TaskListClass};
use super::{NtObject, NtObjectType};

#[path = "desktop/bootstrap.rs"]
mod bootstrap;
pub use bootstrap::{bootstrap_desktop, DesktopBootstrap, DesktopBootstrapError};
#[path = "desktop/identity.rs"]
mod identity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesktopError { WrongType, WrongStation, Busy, InvalidWindow, MissingRoot, NotAttached }

/// The desktop's own window. It belongs to the desktop, not to any process
/// that draws on it: every process attached to this desktop resolves the same
/// handle, including one that has created no window of its own.
#[derive(Clone, Copy)]
pub struct DesktopRoot { hwnd: NonZeroU32 }
impl DesktopRoot {
    /// The handle every attached process sees for this desktop. # C: O(1)
    pub fn hwnd(&self) -> u32 { self.hwnd.get() }
}

pub struct NtDesktop {
    station: Arc<NtObject>,
    root: Spinlock<Option<DesktopRoot>, TaskListClass>,
}
impl NtDesktop {
    /// Constructor is reached only through typed NT object creation. # C: O(1)
    pub(super) fn new(station: Arc<NtObject>) -> Result<Self, DesktopError> {
        if station.kind() != NtObjectType::WindowStation { return Err(DesktopError::WrongType); }
        Ok(Self { station, root: Spinlock::new(None) })
    }
    /// Retain the canonical station, not its process-local handle or numeric ID. # C: O(1)
    pub fn station(&self) -> Arc<NtObject> { Arc::clone(&self.station) }
    /// Establish this desktop's own window, or report the one it already has.
    /// The first caller names the handle and every later caller — a second
    /// process attaching to the same desktop — is answered with it, so one
    /// desktop has one desktop window rather than one per process.
    /// # C: O(1)
    pub fn publish_root(&self, hwnd: u32) -> Result<u32, DesktopError> {
        let hwnd = NonZeroU32::new(hwnd).ok_or(DesktopError::InvalidWindow)?;
        let mut root = self.root.lock();
        match root.as_ref() { Some(old) => Ok(old.hwnd.get()), None => { *root = Some(DesktopRoot { hwnd }); Ok(hwnd.get()) } }
    }
    /// This desktop's window, once it has one. # C: O(1)
    pub fn root(&self) -> Result<DesktopRoot, DesktopError> { let root = *self.root.lock(); root.ok_or(DesktopError::MissingRoot) }
    /// Retire this desktop's window at desktop teardown. # C: O(1)
    pub fn clear_root(&self, hwnd: u32) -> bool {
        let mut root = self.root.lock();
        if !root.as_ref().is_some_and(|r| r.hwnd.get() == hwnd) { return false; }
        *root = None; true
    }
}

impl NtObject {
    /// Create a typed payload outside namespace/GUI locks. # C: O(1)
    pub fn new_desktop(id: u64, station: Arc<NtObject>) -> Result<Arc<Self>, DesktopError> {
        let desktop = Arc::new(NtDesktop::new(station)?);
        let mut object = Self::new(NtObjectType::Desktop, id);
        Arc::get_mut(&mut object).ok_or(DesktopError::Busy)?.desktop = Some(desktop);
        Ok(object)
    }
    /// Resolve the payload only on the typed object; handles resolve through NtHandleTable. # C: O(1)
    pub fn desktop(&self) -> Option<Arc<NtDesktop>> { self.desktop.clone() }
}

/// Embedded in canonical thread state; callers serialize against GUI-user creation.
#[derive(Default, Clone)]
pub struct ThreadDesktop { object: Option<Arc<NtObject>> }
impl ThreadDesktop {
    /// Retain membership for child initialization or HWND-zero resolution. # C: O(1)
    pub fn object(&self) -> Option<Arc<NtObject>> { self.object.clone() }
    /// The desktop window of the desktop this thread is attached to. The same
    /// handle in every attached process; no process's handle namespace is
    /// substituted for it. # C: O(1)
    pub fn resolve_root(&self, station: &Arc<NtObject>) -> Result<u32, DesktopError> {
        let payload = self.object.as_ref().ok_or(DesktopError::NotAttached)?.desktop().ok_or(DesktopError::WrongType)?;
        if !Arc::ptr_eq(&payload.station, station) { return Err(DesktopError::WrongStation); }
        Ok(payload.root()?.hwnd())
    }
    /// Validate station identity before busy state; no mutation on rejection. # C: O(1)
    pub fn select(&mut self, station: &Arc<NtObject>, desktop: Arc<NtObject>, has_users: bool) -> Result<(), DesktopError> {
        let payload = desktop.desktop().ok_or(DesktopError::WrongType)?;
        if !Arc::ptr_eq(&payload.station, station) { return Err(DesktopError::WrongStation); }
        let same = self.object.as_ref().is_some_and(|old| Arc::ptr_eq(old, &desktop));
        if !same && has_users { return Err(DesktopError::Busy); }
        self.object = Some(desktop); Ok(())
    }
    /// Default attachment never overwrites a thread's explicit desktop. # C: O(1)
    pub fn inherit_default(&mut self, selected: &Self) {
        if self.object.is_none() { self.object = selected.object(); }
    }
    /// Same-process child publication consumes process default, never creator selection.
    /// Process/child locks are never nested. # C: O(1)
    pub fn inherit_thread(parent: &crate::Task, child: &crate::Task) -> bool {
        if !Arc::ptr_eq(&parent.thread_group, &child.thread_group) { return false; }
        let selected = parent.thread_group.nt_default_desktop.lock().clone();
        child.nt_desktop.lock().inherit_default(&selected); true
    }
    /// Call after canonical GUI users retire; release returned reference outside the Task lock. # C: O(1)
    pub fn detach(&mut self) -> Option<Arc<NtObject>> { self.object.take() }
}

#[cfg(test)]
#[path = "desktop/tests.rs"]
mod tests;
