//! Admission precedes complete compositor message batches and geometry mutations.
use super::*;

impl WindowManager {
    /// Caller retains exclusive canonical owner access until the batch is posted.
    /// # C: O(windows + queues)
    pub fn check_message_capacity(&self, id: WindowId, count: usize) -> Result<(), WindowError> {
        let owner = self.get(id).ok_or(WindowError::NoSuchWindow)?.owner_tid;
        if self.queue_has_capacity(owner, count) { Ok(()) } else { Err(WindowError::QueueFull) }
    }

    /// Reserve only posted move/size notifications; paint readiness owns no posted slot.
    /// Zero-sized windows do not acquire an empty dirty rectangle.
    /// # C: O(windows + queues + dirty regions); # Sleeps: no
    pub fn configure_compositor_window(&mut self, id: WindowId, next: WindowRect) -> Result<(), WindowError> {
        let old = self.rect(id).ok_or(WindowError::NoSuchWindow)?;
        let width = next.right.checked_sub(next.left).filter(|n| *n >= 0).ok_or(WindowError::InvalidParent)?;
        let height = next.bottom.checked_sub(next.top).filter(|n| *n >= 0).ok_or(WindowError::InvalidParent)?;
        let moved = (old.left, old.top) != (next.left, next.top);
        let resized = (old.right as i64 - old.left as i64, old.bottom as i64 - old.top as i64) != (width as i64, height as i64);
        let repaint = resized && width != 0 && height != 0;
        self.check_message_capacity(id, usize::from(moved) + usize::from(resized))?;
        self.set_rect(id, next)?;
        if moved {
            self.post_to_window(id, WinMessage { hwnd: Some(id), message: WM_MOVE, wparam: 0, lparam: mouse_lparam(next.left, next.top) })?;
        }
        if resized {
            self.post_to_window(id, WinMessage { hwnd: Some(id), message: WM_SIZE, wparam: 0, lparam: mouse_lparam(width, height) })?;
        }
        if repaint { self.invalidate(id, None)?; }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/compositor_queue.rs"]
mod tests;
