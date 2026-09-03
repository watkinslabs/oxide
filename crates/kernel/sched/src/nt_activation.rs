//! Per-thread native activation-context stack ownership.

use alloc::{sync::Arc, vec::Vec};

use crate::nt_object::{NtHandle, NtObject};

const MAX_DEPTH: usize = 64;

#[derive(Clone)]
pub struct Frame {
    cookie: u64,
    handle: NtHandle,
    object: Arc<NtObject>,
}

impl Frame {
    pub fn cookie(&self) -> u64 { self.cookie }
    pub fn handle(&self) -> NtHandle { self.handle }
    pub fn object(&self) -> Arc<NtObject> { Arc::clone(&self.object) }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DeactivateError { NotFound, Early, NoMemory }

pub struct Stack {
    frames: Vec<Frame>,
    next_cookie: u64,
}

impl Stack {
    pub const fn new() -> Self { Self { frames: Vec::new(), next_cookie: 1 } }

    /// Publish one activation frame after its object reference is acquired.
    /// # C: O(depth), bounded by `MAX_DEPTH`
    pub fn push(&mut self, handle: NtHandle, object: Arc<NtObject>) -> Option<u64> {
        if self.frames.len() >= MAX_DEPTH || self.frames.try_reserve(1).is_err() { return None; }
        let cookie = self.next_cookie();
        self.frames.push(Frame { cookie, handle, object });
        Some(cookie)
    }

    /// Return the active frame without changing stack ownership. # C: O(1)
    pub fn top(&self) -> Option<Frame> { self.frames.last().cloned() }

    /// Remove the named frame and all newer frames when forced. # C: O(depth)
    pub fn deactivate(&mut self, cookie: u64, force: bool) -> Result<Vec<Frame>, DeactivateError> {
        let Some(index) = self.frames.iter().rposition(|frame| frame.cookie == cookie) else {
            return Err(DeactivateError::NotFound);
        };
        if index + 1 != self.frames.len() && !force { return Err(DeactivateError::Early); }
        let count = self.frames.len() - index;
        let mut removed = Vec::new();
        if removed.try_reserve_exact(count).is_err() { return Err(DeactivateError::NoMemory); }
        while self.frames.len() > index { removed.push(self.frames.pop().unwrap()); }
        Ok(removed)
    }

    /// Remove every frame without allocating. # C: O(depth)
    pub fn clear(&mut self) -> Vec<Frame> {
        let mut removed = core::mem::take(&mut self.frames);
        removed.reverse();
        removed
    }

    pub fn len(&self) -> usize { self.frames.len() }

    fn next_cookie(&mut self) -> u64 {
        loop {
            let cookie = self.next_cookie.max(1);
            self.next_cookie = cookie.wrapping_add(1).max(1);
            if self.frames.iter().all(|frame| frame.cookie != cookie) { return cookie; }
        }
    }
}

impl Default for Stack { fn default() -> Self { Self::new() } }

/// Release semantic references after frames leave a task stack. The stack lock
/// must be dropped before this function reaches the process handle table.
/// # C: O(frame count * process handle count)
pub fn release_frames(task: &crate::Task, frames: Vec<Frame>) {
    for frame in frames {
        let Some(context) = frame.object.activation_context() else { continue; };
        if context.release() == Some(true) {
            let _ = task.thread_group.nt_handles().close(frame.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nt_object::{NtHandleTable, NtObjectType};
    use crate::SchedClass;

    fn context(table: &NtHandleTable) -> (NtHandle, Arc<NtObject>) {
        let object = table.new_activation_context();
        let handle = table.insert(Arc::clone(&object), 0).unwrap();
        assert_eq!(object.kind(), NtObjectType::ActivationContext);
        (handle, object)
    }

    #[test]
    fn nested_frames_are_lifo_and_early_pop_requires_force() {
        let table = NtHandleTable::new();
        let (first_handle, first) = context(&table);
        let (second_handle, second) = context(&table);
        let mut stack = Stack::new();
        let first_cookie = stack.push(first_handle, first).unwrap();
        let second_cookie = stack.push(second_handle, second).unwrap();
        assert!(matches!(stack.deactivate(first_cookie, false), Err(DeactivateError::Early)));
        let removed = stack.deactivate(first_cookie, true).unwrap();
        assert_eq!(removed.len(), 2);
        assert_eq!(removed[0].cookie(), second_cookie);
        assert_eq!(removed[1].cookie(), first_cookie);
        assert_eq!(stack.len(), 0);
    }

    #[test]
    fn unknown_cookie_leaves_stack_unchanged() {
        let table = NtHandleTable::new();
        let (handle, object) = context(&table);
        let mut stack = Stack::new();
        stack.push(handle, object).unwrap();
        assert!(matches!(stack.deactivate(u64::MAX, true), Err(DeactivateError::NotFound)));
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn depth_limit_rejects_without_replacing_the_active_frame() {
        let table = NtHandleTable::new();
        let mut stack = Stack::new();
        let mut last = 0;
        for _ in 0..MAX_DEPTH {
            let (handle, object) = context(&table);
            last = stack.push(handle, object).unwrap();
        }
        let (extra_handle, extra) = context(&table);
        assert_eq!(stack.push(extra_handle, extra), None);
        assert_eq!(stack.len(), MAX_DEPTH);
        assert_eq!(stack.top().unwrap().cookie(), last);
    }

    #[test]
    fn clear_returns_every_frame_in_release_order() {
        let table = NtHandleTable::new();
        let mut stack = Stack::new();
        let (first_handle, first) = context(&table);
        let (second_handle, second) = context(&table);
        let first_cookie = stack.push(first_handle, first).unwrap();
        let second_cookie = stack.push(second_handle, second).unwrap();
        let frames = stack.clear();
        assert_eq!(frames.iter().map(Frame::cookie).collect::<Vec<_>>(),
            alloc::vec![second_cookie, first_cookie]);
        assert_eq!(stack.top().map(|frame| frame.cookie()), None);
    }

    #[test]
    fn stack_reference_keeps_identity_until_thread_cleanup() {
        let task = crate::Task::new(7301, "actctx", SchedClass::Normal { weight: 1024 });
        let table = task.thread_group.nt_handles();
        let object = table.new_activation_context();
        let context = object.activation_context().unwrap();
        let handle = table.insert(Arc::clone(&object), 0).unwrap();
        assert!(context.add_ref());
        task.nt_activation_stack.lock().push(handle, object).unwrap();
        assert_eq!(context.release(), Some(false));
        assert!(table.contains(handle));
        let frames = task.nt_activation_stack.lock().clear();
        release_frames(&task, frames);
        assert!(!table.contains(handle));
        assert_eq!(context.references(), 0);
    }
}
