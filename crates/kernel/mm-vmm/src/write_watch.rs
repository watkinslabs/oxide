use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::ops::Bound;
use sync::{AddressSpace as AddressSpaceClass, Spinlock};

use crate::{Error, KResult};

/// Per-mm write-watch ownership. The VMM owns both the watched range and the
/// dirty-page set; NT only translates the ABI and never keeps a second map.
pub(crate) struct WriteWatchState { watched: BTreeSet<u64>, dirty: BTreeSet<u64> }
impl WriteWatchState { pub(crate) fn new() -> Self { Self { watched: BTreeSet::new(), dirty: BTreeSet::new() } } }
pub(crate) type WriteWatchLock = Spinlock<WriteWatchState, AddressSpaceClass>;

/// Register every page in one MEM_WRITE_WATCH VMA. # C: O(number of pages)
pub(crate) fn register(lock: &WriteWatchLock, base: u64, size: usize) -> KResult<()> {
    let page = hal::PAGE_SIZE_BYTES;
    if size == 0 || base & (page - 1) != 0 || size as u64 % page != 0 { return Err(Error::Inval); }
    let end = base.checked_add(size as u64).ok_or(Error::Inval)?;
    let mut state = lock.lock();
    for va in (base..end).step_by(page as usize) { state.watched.insert(va); }
    Ok(())
}

/// Remove ownership for an unmapped write-watch range. # C: O(number of pages)
pub(crate) fn unregister(lock: &WriteWatchLock, base: u64, size: usize) {
    let page = hal::PAGE_SIZE_BYTES; let end = base.saturating_add(size as u64);
    let mut state = lock.lock();
    for va in (base..end).step_by(page as usize) { state.watched.remove(&va); state.dirty.remove(&va); }
}

/// Record the first write to a watched page. # C: O(log N)
pub(crate) fn mark(lock: &WriteWatchLock, va: u64) {
    let page = va & !(hal::PAGE_SIZE_BYTES - 1); let mut state = lock.lock();
    if state.watched.contains(&page) { state.dirty.insert(page); }
}

/// Return dirty page bases and optionally clear returned state. # C: O(N)
pub(crate) fn query(lock: &WriteWatchLock, base: u64, size: usize, cap: usize, reset: bool) -> KResult<Vec<u64>> {
    let page = hal::PAGE_SIZE_BYTES;
    if size == 0 || base & (page - 1) != 0 || size as u64 % page != 0 || cap == 0 { return Err(Error::Inval); }
    let end = base.checked_add(size as u64).ok_or(Error::Inval)?; let mut state = lock.lock();
    if state.watched.range(base..end).count() != size / page as usize { return Err(Error::Inval); }
    let out: Vec<u64> = state.dirty.range((Bound::Included(base), Bound::Excluded(end))).take(cap).copied().collect();
    if reset { for va in &out { state.dirty.remove(va); } } Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    #[test]
    fn dirty_pages_are_canonical_and_reset_is_scoped() {
        let lock = WriteWatchLock::new(WriteWatchState::new()); register(&lock, 0x4000, hal::PAGE_SIZE_BYTES as usize * 3).unwrap();
        mark(&lock, 0x4abc); mark(&lock, 0x6abc); mark(&lock, 0x6abc);
        assert_eq!(query(&lock, 0x4000, hal::PAGE_SIZE_BYTES as usize * 3, 8, false).unwrap(), vec![0x4000, 0x6000]);
        assert_eq!(query(&lock, 0x4000, hal::PAGE_SIZE_BYTES as usize, 8, true).unwrap(), vec![0x4000]);
        assert_eq!(query(&lock, 0x4000, hal::PAGE_SIZE_BYTES as usize * 3, 8, true).unwrap(), vec![0x6000]);
        assert!(query(&lock, 0x4000, hal::PAGE_SIZE_BYTES as usize * 3, 8, false).unwrap().is_empty());
    }
    #[test]
    fn positive_control_marks_a_write() {
        let lock = WriteWatchLock::new(WriteWatchState::new()); register(&lock, 0x8000, hal::PAGE_SIZE_BYTES as usize).unwrap(); mark(&lock, 0x8123);
        assert_eq!(query(&lock, 0x8000, hal::PAGE_SIZE_BYTES as usize, 1, false).unwrap(), vec![0x8000]);
    }
}
