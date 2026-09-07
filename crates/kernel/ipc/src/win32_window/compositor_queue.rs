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
        let next = self.compositor_parent_space(id, next)?;
        let old = self.rect(id).ok_or(WindowError::NoSuchWindow)?;
        let width = next.right.checked_sub(next.left).filter(|n| *n >= 0).ok_or(WindowError::InvalidParent)?;
        let height = next.bottom.checked_sub(next.top).filter(|n| *n >= 0).ok_or(WindowError::InvalidParent)?;
        let moved = (old.left, old.top) != (next.left, next.top);
        let resized = (old.right as i64 - old.left as i64, old.bottom as i64 - old.top as i64) != (width as i64, height as i64);
        let repaint = resized && width != 0 && height != 0;
        self.check_message_capacity(id, usize::from(moved) + usize::from(resized))?;
        let insets = self.get(id).ok_or(WindowError::NoSuchWindow)?.client_rect.map(|client| nonclient_create::insets(old, client));
        self.set_rect(id, next)?;
        if let Some(insets) = insets {
            let client = nonclient_create::inset_client(next, insets).ok_or(WindowError::InvalidParent)?;
            let record = self.windows.iter_mut().find(|(window, _)| *window == id).ok_or(WindowError::NoSuchWindow)?;
            record.1.client_rect = Some(client);
        }
        let client = self.client_rect_raw(id).unwrap_or(next);
        if moved {
            self.post_to_window(id, WinMessage { hwnd: Some(id), message: WM_MOVE, wparam: 0, lparam: mouse_lparam(client.left, client.top) })?;
        }
        if resized {
            self.post_to_window(id, WinMessage { hwnd: Some(id), message: WM_SIZE, wparam: 0,
                lparam: mouse_lparam(client.right - client.left, client.bottom - client.top) })?;
        }
        if repaint { self.invalidate(id, None)?; }
        Ok(())
    }

    /// A child's canonical rectangle is stated in its parent's client
    /// coordinates; the compositor reports one in the parent's window
    /// coordinates, which is what an X child's position is relative to.
    /// # C: O(N_windows)
    fn compositor_parent_space(&self, id: WindowId, next: WindowRect) -> Result<WindowRect, WindowError> {
        let Some(parent) = self.get(id).ok_or(WindowError::NoSuchWindow)?.parent else { return Ok(next); };
        let (Some(window), Some(client)) = (self.rect(parent), self.client_rect_raw(parent)) else { return Ok(next); };
        let (dx, dy) = nonclient_create::client_origin(window, client);
        Ok(WindowRect { left: next.left.wrapping_sub(dx), top: next.top.wrapping_sub(dy),
            right: next.right.wrapping_sub(dx), bottom: next.bottom.wrapping_sub(dy) })
    }
}

#[cfg(test)]
#[path = "tests/compositor_queue.rs"]
mod tests;
