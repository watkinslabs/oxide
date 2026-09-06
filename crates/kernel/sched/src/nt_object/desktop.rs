//! Canonical desktop payload and thread membership; no auxiliary namespace.
use alloc::sync::{Arc, Weak};
use core::num::NonZeroU32;
use sync::{Spinlock, TaskList as TaskListClass};
use crate::thread_group::ThreadGroup;
use super::{NtObject, NtObjectType};

#[path = "desktop/bootstrap.rs"]
mod bootstrap;
pub use bootstrap::{bootstrap_desktop, DesktopBootstrap, DesktopBootstrapError};
#[path = "desktop/identity.rs"]
mod identity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesktopError { WrongType, WrongStation, Busy, InvalidWindow, RootOccupied, MissingRoot, NotAttached }

/// A reference to the existing window owner, never a second HWND record.
#[derive(Clone)]
pub struct DesktopRoot { process: Weak<ThreadGroup>, hwnd: NonZeroU32 }
impl DesktopRoot {
    /// Upgrade canonical process identity; numeric PID/HWND reuse cannot substitute. # C: O(1)
    pub fn resolve(&self) -> Option<(Arc<ThreadGroup>, u32)> { Some((self.process.upgrade()?, self.hwnd.get())) }
    fn matches(&self, process: &Arc<ThreadGroup>, hwnd: u32) -> bool {
        self.hwnd.get() == hwnd && self.process.ptr_eq(&Arc::downgrade(process))
    }
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
    /// Publish after the GUI owner creates a real root; no allocation under this lock. # C: O(1)
    pub fn publish_root(&self, process: &Arc<ThreadGroup>, hwnd: u32) -> Result<(), DesktopError> {
        let hwnd = NonZeroU32::new(hwnd).ok_or(DesktopError::InvalidWindow)?;
        let mut root = self.root.lock();
        if let Some(old) = root.as_ref() {
            return if old.matches(process, hwnd.get()) { Ok(()) } else { Err(DesktopError::RootOccupied) };
        }
        *root = Some(DesktopRoot { process: Arc::downgrade(process), hwnd }); Ok(())
    }
    /// Validate without the root lock; a raced destruction cannot leave a published stale root.
    /// Root destruction uses clear_root after canonical GUI removal. # C: O(2 * validate)
    pub fn publish_root_checked(&self, process: &Arc<ThreadGroup>, hwnd: u32, mut validate: impl FnMut() -> bool) -> Result<(), DesktopError> {
        if !validate() { return Err(DesktopError::InvalidWindow); }
        self.publish_root(process, hwnd)?;
        if !validate() { self.clear_root(process, hwnd); return Err(DesktopError::InvalidWindow); }
        Ok(())
    }
    /// Snapshot a root reference; GUI still validates HWND lifetime when resolving. # C: O(1)
    pub fn root(&self) -> Result<DesktopRoot, DesktopError> { self.root.lock().clone().ok_or(DesktopError::MissingRoot) }
    /// Teardown cannot clear another process's equal numeric HWND. # C: O(1)
    pub fn clear_root(&self, process: &Arc<ThreadGroup>, hwnd: u32) -> bool {
        let mut root = self.root.lock();
        if !root.as_ref().is_some_and(|r| r.matches(process, hwnd)) { return false; }
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
    /// HWND-zero resolution retains the real root's process, not the caller's handle namespace. # C: O(1)
    pub fn resolve_root(&self, station: &Arc<NtObject>) -> Result<(Arc<ThreadGroup>, u32), DesktopError> {
        let payload = self.object.as_ref().ok_or(DesktopError::NotAttached)?.desktop().ok_or(DesktopError::WrongType)?;
        if !Arc::ptr_eq(&payload.station, station) { return Err(DesktopError::WrongStation); }
        payload.root()?.resolve().ok_or(DesktopError::MissingRoot)
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
