//! Deferred window-position batches: one accumulator per BeginDeferWindowPos
//! handle, merging repeated entries for the same window the way the batch
//! call does, and replayed in order when the batch ends.
use alloc::vec::Vec;
use super::WindowId;

pub const SWP_NOSIZE: u32 = 0x0001;
pub const SWP_NOMOVE: u32 = 0x0002;
pub const SWP_NOZORDER: u32 = 0x0004;
pub const SWP_NOREDRAW: u32 = 0x0008;
pub const SWP_NOACTIVATE: u32 = 0x0010;
pub const SWP_FRAMECHANGED: u32 = 0x0020;
pub const SWP_SHOWWINDOW: u32 = 0x0040;
pub const SWP_HIDEWINDOW: u32 = 0x0080;
pub const SWP_NOCOPYBITS: u32 = 0x0100;
pub const SWP_NOOWNERZORDER: u32 = 0x0200;

/// Flags a repeated entry keeps only where the new request also carries them.
const MERGE_INTERSECT: u32 = SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOREDRAW
    | SWP_NOACTIVATE | SWP_NOCOPYBITS | SWP_NOOWNERZORDER;
/// Flags a repeated entry gains from the new request.
const MERGE_UNION: u32 = SWP_SHOWWINDOW | SWP_HIDEWINDOW | SWP_FRAMECHANGED;

/// A batch with no requested capacity still reserves room for this many moves.
const DEFAULT_CAPACITY: usize = 8;
/// Upper bound on one batch, so a hostile count cannot exhaust the heap.
const MAX_CAPACITY: usize = 4096;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DeferredPosition {
    pub window: WindowId,
    pub insert_after: u64,
    pub x: i32, pub y: i32, pub cx: i32, pub cy: i32,
    pub flags: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DeferError { InvalidParameter, InvalidHandle, NoMemory }

/// Every open batch of one process, keyed by the handle its opening answered.
#[derive(Default)]
pub struct DeferBatches { batches: Vec<(u32, Vec<DeferredPosition>)>, next_handle: u32 }

impl DeferBatches {
    /// # C: O(1)
    pub const fn new() -> Self { Self { batches: Vec::new(), next_handle: 1 } }

    /// Open one batch, answering its handle. A negative count is refused; a
    /// zero count still reserves room for a handful of moves. # C: O(N_batches)
    pub fn begin(&mut self, count: i32) -> Result<u32, DeferError> {
        let count = usize::try_from(count).map_err(|_| DeferError::InvalidParameter)?;
        let count = if count == 0 { DEFAULT_CAPACITY } else { count.min(MAX_CAPACITY) };
        let mut entries = Vec::new();
        entries.try_reserve_exact(count).map_err(|_| DeferError::NoMemory)?;
        self.batches.try_reserve(1).map_err(|_| DeferError::NoMemory)?;
        let handle = self.next_handle;
        self.next_handle = self.next_handle.checked_add(1).ok_or(DeferError::NoMemory)?;
        self.batches.push((handle, entries));
        Ok(handle)
    }

    /// Add one move to an open batch, or merge it into the entry already
    /// present for the same window. # C: O(N_batches + N_entries)
    pub fn defer(&mut self, handle: u32, position: DeferredPosition) -> Result<(), DeferError> {
        let index = self.batches.iter().position(|(open, _)| *open == handle).ok_or(DeferError::InvalidHandle)?;
        let entries = &mut self.batches[index].1;
        if let Some(existing) = entries.iter_mut().find(|entry| entry.window == position.window) {
            if position.flags & SWP_NOZORDER == 0 { existing.insert_after = position.insert_after; }
            if position.flags & SWP_NOMOVE == 0 { existing.x = position.x; existing.y = position.y; }
            if position.flags & SWP_NOSIZE == 0 { existing.cx = position.cx; existing.cy = position.cy; }
            existing.flags &= position.flags | !MERGE_INTERSECT;
            existing.flags |= position.flags & MERGE_UNION;
            return Ok(());
        }
        entries.try_reserve(1).map_err(|_| DeferError::NoMemory)?;
        entries.push(position);
        Ok(())
    }

    /// Close one batch and answer its moves in the order they were added.
    /// # C: O(N_batches)
    pub fn end(&mut self, handle: u32) -> Result<Vec<DeferredPosition>, DeferError> {
        let index = self.batches.iter().position(|(open, _)| *open == handle).ok_or(DeferError::InvalidHandle)?;
        Ok(self.batches.remove(index).1)
    }

    /// Number of open batches. # C: O(1)
    pub fn len(&self) -> usize { self.batches.len() }
    /// Whether no batch is open. # C: O(1)
    pub fn is_empty(&self) -> bool { self.batches.is_empty() }
}

#[cfg(test)]
#[path = "defer/tests.rs"]
mod tests;
