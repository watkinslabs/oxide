//! Viewer chain, format listeners and window-destruction cleanup.
use super::*;

impl ClipboardManager {
    /// Install a viewer, answering the one it displaces. A caller that names
    /// the viewer it believes is current gets `Pending` when that belief is
    /// stale, which is the caller's cue to walk the chain by message.
    /// # C: O(1)
    pub fn set_viewer(&mut self, viewer: Option<WindowId>, previous: Option<WindowId>)
        -> Result<(Option<WindowId>, Option<WindowId>), ClipboardError> {
        let old = self.viewer;
        if previous.is_some() && self.viewer != previous { return Err(ClipboardError::Pending); }
        self.viewer = viewer;
        Ok((old, self.owner))
    }

    /// Current first viewer. # C: O(1)
    pub const fn viewer(&self) -> Option<WindowId> { self.viewer }

    /// Register one format listener. Registering the same window twice is a
    /// parameter error. # C: O(N_listeners)
    pub fn add_listener(&mut self, window: WindowId) -> Result<(), ClipboardError> {
        if self.listeners.contains(&window) { return Err(ClipboardError::InvalidParameter); }
        self.listeners.try_reserve(1).map_err(|_| ClipboardError::NoMemory)?;
        self.listeners.push(window);
        Ok(())
    }

    /// Remove one format listener; removing an unregistered window is a
    /// parameter error. # C: O(N_listeners)
    pub fn remove_listener(&mut self, window: WindowId) -> Result<(), ClipboardError> {
        let index = self.listeners.iter().position(|entry| *entry == window)
            .ok_or(ClipboardError::InvalidParameter)?;
        self.listeners.remove(index);
        Ok(())
    }

    /// Windows a content change must post WM_CLIPBOARDUPDATE to. # C: O(N_listeners)
    pub fn listeners(&self) -> &[WindowId] { &self.listeners }

    /// Retire every reference to a window being destroyed, answering the
    /// viewer a still-open transaction would have to notify. # C: O(N_formats² + N_listeners)
    pub fn cleanup_window(&mut self, window: WindowId) -> ClipboardNotify {
        let _ = self.remove_listener(window);
        if self.viewer == Some(window) { self.viewer = None; }
        if self.owner == Some(window) { let _ = self.release_owner(window); }
        if self.open_window != Some(window) { return ClipboardNotify::default(); }
        ClipboardNotify { viewer: self.close_transaction(), owner: self.owner }
    }

    /// Retire an exiting thread's open transaction. # C: O(N_formats)
    pub fn cleanup_thread(&mut self, thread: u64) -> ClipboardNotify {
        if self.open_thread != Some(thread) { return ClipboardNotify::default(); }
        ClipboardNotify { viewer: self.close_transaction(), owner: self.owner }
    }
}
