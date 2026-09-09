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
        let client = insets.map(|insets| nonclient_create::inset_client(next, insets).ok_or(WindowError::InvalidParent)).transpose()?;
        self.set_rect(id, next)?;
        if let Some(client) = client {
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
        // A window that only moved keeps its pixels: the display moved them
        // with it and nothing of it was revealed. A window that changed size
        // exposes area no paint has ever covered, and the band its frame
        // occupies is sized from the window rectangle, so the frame and every
        // descendant are invalidated with it and the background is erased.
        if repaint { self.redraw_tree(id, None, FRAME_REDRAW, |_, _, region| region.try_copy())?; }
        Ok(())
    }

    /// One rectangle of a window the display no longer holds pixels for,
    /// stated in the window's own coordinates with its origin at the window's
    /// top left. Canonical damage is stated in client coordinates, so the
    /// client origin comes off the rectangle before it is unioned in.
    /// # C: O(windows^2 + region operations); # Sleeps: no
    pub fn expose_compositor_window(&mut self, id: WindowId, exposed: WindowRect) -> Result<(), WindowError> {
        let window = self.rect(id).ok_or(WindowError::NoSuchWindow)?;
        let client = self.client_rect_raw(id).unwrap_or(window);
        let (dx, dy) = nonclient_create::client_origin(window, client);
        let local = WindowRect {
            left: exposed.left.checked_sub(dx).ok_or(WindowError::InvalidParent)?,
            top: exposed.top.checked_sub(dy).ok_or(WindowError::InvalidParent)?,
            right: exposed.right.checked_sub(dx).ok_or(WindowError::InvalidParent)?,
            bottom: exposed.bottom.checked_sub(dy).ok_or(WindowError::InvalidParent)? };
        if local.left >= local.right || local.top >= local.bottom { return Err(WindowError::InvalidParent); }
        let region = PaintRegion::from_rect(local)?;
        self.redraw_tree(id, Some(&region), EXPOSE_REDRAW, |_, _, region| region.try_copy())
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
