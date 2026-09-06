//! Canonical per-message-queue caret ownership.

use super::super::{CaretCommit, CaretError, MessageQueue, WindowId, WindowManager};

fn queue_mut<'a>(manager: &'a mut WindowManager, tid: u64) -> Result<&'a mut MessageQueue, CaretError> {
    manager.queues.iter_mut().find(|(owner, _)| *owner == tid).map(|(_, queue)| queue).ok_or(CaretError::NoQueue)
}

fn owned_window(manager: &WindowManager, tid: u64, hwnd: WindowId) -> Result<(), CaretError> {
    let record = manager.get(hwnd).ok_or(CaretError::InvalidWindow)?;
    if record.owner_tid != tid { return Err(CaretError::WrongThread); }
    Ok(())
}

impl WindowManager {
    pub fn create_caret(&mut self, tid: u64, hwnd: WindowId, width: i32, height: i32) -> Result<CaretCommit, CaretError> {
        owned_window(self, tid, hwnd)?;
        let queue = queue_mut(self, tid)?;
        let transition = queue.caret.create(hwnd, width, height);
        queue.caret_generation = queue.caret_generation.wrapping_add(1);
        Ok(CaretCommit { transition, generation: queue.caret_generation })
    }

    pub fn destroy_caret(&mut self, tid: u64) -> Result<CaretCommit, CaretError> {
        let queue = queue_mut(self, tid)?;
        let transition = queue.caret.destroy().ok_or(CaretError::NoCaret)?;
        queue.caret_generation = queue.caret_generation.wrapping_add(1);
        Ok(CaretCommit { transition, generation: queue.caret_generation })
    }

    pub fn set_caret_pos(&mut self, tid: u64, x: i32, y: i32) -> Result<CaretCommit, CaretError> {
        let queue = queue_mut(self, tid)?;
        let transition = queue.caret.set_pos(x, y).ok_or(CaretError::NoCaret)?;
        queue.caret_generation = queue.caret_generation.wrapping_add(1);
        Ok(CaretCommit { transition, generation: queue.caret_generation })
    }

    pub fn show_caret(&mut self, tid: u64, hwnd: Option<WindowId>) -> Result<CaretCommit, CaretError> {
        if let Some(hwnd) = hwnd { owned_window(self, tid, hwnd)?; }
        let queue = queue_mut(self, tid)?;
        let transition = queue.caret.show(hwnd).ok_or(CaretError::NoCaret)?;
        queue.caret_generation = queue.caret_generation.wrapping_add(1);
        Ok(CaretCommit { transition, generation: queue.caret_generation })
    }

    pub fn hide_caret(&mut self, tid: u64, hwnd: Option<WindowId>) -> Result<CaretCommit, CaretError> {
        if let Some(hwnd) = hwnd { owned_window(self, tid, hwnd)?; }
        let queue = queue_mut(self, tid)?;
        let transition = queue.caret.hide(hwnd).ok_or(CaretError::NoCaret)?;
        queue.caret_generation = queue.caret_generation.wrapping_add(1);
        Ok(CaretCommit { transition, generation: queue.caret_generation })
    }
}
