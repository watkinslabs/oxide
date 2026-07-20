use alloc::boxed::Box;
use alloc::vec::Vec;

use block::{BlockError, KResult};

use super::{Slot, PAGE_BYTES};

/// Metadata carried for each logical zram page.  Linux allocates this table
/// when `disksize` initializes zram; every addressable page therefore has one
/// canonical entry before the first data I/O.
struct Entry {
    slot: Slot,
    generation: u64,
    idle: bool,
    last_access_ns: u64,
}

impl Entry {
    fn empty() -> Self { Self { slot: Slot::Empty, generation: 0, idle: false, last_access_ns: 0 } }
}

/// Keep each metadata allocation bounded by one PMM page, derived from the
/// target's page size and the actual entry layout rather than a fixed count.
const ENTRIES_PER_CHUNK: usize = {
    let entries = PAGE_BYTES / core::mem::size_of::<Entry>();
    if entries == 0 { 1 } else { entries }
};

pub(crate) struct SlotTable {
    len: usize,
    chunks: Vec<Option<Box<[Entry]>>>,
}

impl SlotTable {
    /// # C: O(1)
    pub(crate) fn new() -> Self { Self { len: 0, chunks: Vec::new() } }

    /// # C: O(1)
    pub(crate) fn len(&self) -> usize { self.len }

    /// Allocate all table chunks while initializing capacity.  This is an
    /// initialization failure boundary, not a deferred write-path allocation:
    /// Linux `zram_meta_alloc()` either obtains metadata for every page or
    /// rejects `disksize` with ENOMEM.
    /// # C: O(number of metadata chunks × entries per chunk)
    pub(crate) fn resize(&mut self, len: usize) -> KResult<()> {
        let chunks = len.checked_add(ENTRIES_PER_CHUNK - 1).ok_or(BlockError::Einval)? / ENTRIES_PER_CHUNK;
        let additional = chunks.saturating_sub(self.chunks.len());
        self.chunks.try_reserve_exact(additional).map_err(|_| BlockError::Enomem)?;
        self.chunks.truncate(chunks);
        while self.chunks.len() < chunks {
            let mut entries = Vec::new();
            entries.try_reserve_exact(ENTRIES_PER_CHUNK).map_err(|_| BlockError::Enomem)?;
            entries.resize_with(ENTRIES_PER_CHUNK, Entry::empty);
            self.chunks.push(Some(entries.into_boxed_slice()));
        }
        self.len = len;
        Ok(())
    }

    /// # C: O(number of metadata chunks)
    pub(crate) fn clear(&mut self) {
        self.len = 0;
        self.chunks.clear();
    }

    /// # C: O(1)
    pub(crate) fn get(&self, index: usize) -> Option<&Slot> {
        if index >= self.len { return None; }
        let chunk = index / ENTRIES_PER_CHUNK;
        let offset = index % ENTRIES_PER_CHUNK;
        Some(&self.chunks[chunk].as_ref().expect("eager zram metadata chunk")[offset].slot)
    }

    fn entry_mut(&mut self, index: usize) -> KResult<&mut Entry> {
        if index >= self.len { return Err(BlockError::Einval); }
        let chunk = index / ENTRIES_PER_CHUNK;
        let offset = index % ENTRIES_PER_CHUNK;
        Ok(&mut self.chunks[chunk].as_mut().expect("eager zram metadata chunk")[offset])
    }

    /// # C: O(1)
    pub(crate) fn replace(&mut self, index: usize, replacement: Slot) -> KResult<Slot> {
        if index >= self.len { return Err(BlockError::Einval); }
        let entry = self.entry_mut(index)?;
        entry.generation = entry.generation.checked_add(1).ok_or(BlockError::Eio)?;
        Ok(core::mem::replace(&mut entry.slot, replacement))
    }

    /// Canonical mutation generation for reserve/commit revalidation. # C: O(1)
    pub(crate) fn generation(&self, index: usize) -> Option<u64> {
        if index >= self.len { return None; }
        let chunk = index / ENTRIES_PER_CHUNK;
        let offset = index % ENTRIES_PER_CHUNK;
        Some(self.chunks[chunk].as_ref().expect("eager zram metadata chunk")[offset].generation)
    }

    /// # C: O(1)
    pub(crate) fn idle(&self, index: usize) -> Option<bool> {
        if index >= self.len { return None; }
        let chunk = index / ENTRIES_PER_CHUNK;
        let offset = index % ENTRIES_PER_CHUNK;
        Some(self.chunks[chunk].as_ref().expect("eager zram metadata chunk")[offset].idle)
    }

    /// # C: O(1)
    pub(crate) fn last_access_ns(&self, index: usize) -> Option<u64> {
        if index >= self.len { return None; }
        let chunk = index / ENTRIES_PER_CHUNK;
        let offset = index % ENTRIES_PER_CHUNK;
        Some(self.chunks[chunk].as_ref().expect("eager zram metadata chunk")[offset].last_access_ns)
    }

    /// # C: O(1)
    pub(crate) fn set_idle(&mut self, index: usize, idle: bool) -> KResult<()> {
        self.entry_mut(index)?.idle = idle;
        Ok(())
    }

    /// # C: O(1)
    pub(crate) fn set_last_access_ns(&mut self, index: usize, access: u64) -> KResult<()> {
        self.entry_mut(index)?.last_access_ns = access;
        Ok(())
    }

    /// # C: O(1)
    pub(crate) fn get_mut(&mut self, index: usize) -> Option<&mut Slot> {
        if index >= self.len { return None; }
        let chunk = index / ENTRIES_PER_CHUNK;
        let offset = index % ENTRIES_PER_CHUNK;
        Some(&mut self.chunks[chunk].as_mut().expect("eager zram metadata chunk")[offset].slot)
    }

    #[cfg(test)]
    /// # C: O(number of chunks)
    pub(crate) fn allocated_chunk_count(&self) -> usize { self.chunks.iter().flatten().count() }
}

#[cfg(test)]
mod tests {
    use super::{Slot, SlotTable, ENTRIES_PER_CHUNK};

    /// One page beyond a metadata chunk ensures capacity follows the logical
    /// zram-page count rather than any fixed small table limit.
    const FIRST_SLOT_AFTER_CHUNK: usize = ENTRIES_PER_CHUNK;
    const LOGICAL_PAGE_COUNT: usize = FIRST_SLOT_AFTER_CHUNK + 1;
    const SAME_FILL_WORD: usize = 0;

    #[test]
    fn logical_capacity_spans_all_requested_zram_pages() {
        let mut table = SlotTable::new();
        table.resize(LOGICAL_PAGE_COUNT).unwrap();
        assert_eq!(table.len(), LOGICAL_PAGE_COUNT);
        assert!(matches!(table.get(FIRST_SLOT_AFTER_CHUNK), Some(Slot::Empty)));
        table.replace(FIRST_SLOT_AFTER_CHUNK, Slot::Same(SAME_FILL_WORD)).unwrap();
        assert!(matches!(table.get(FIRST_SLOT_AFTER_CHUNK), Some(Slot::Same(SAME_FILL_WORD))));
    }

    #[test]
    fn shrinking_releases_only_out_of_range_metadata_chunks() {
        let mut table = SlotTable::new();
        table.resize(LOGICAL_PAGE_COUNT).unwrap();
        table.replace(FIRST_SLOT_AFTER_CHUNK, Slot::Same(SAME_FILL_WORD)).unwrap();
        table.resize(FIRST_SLOT_AFTER_CHUNK).unwrap();
        assert_eq!(table.len(), FIRST_SLOT_AFTER_CHUNK);
        assert!(table.get(FIRST_SLOT_AFTER_CHUNK).is_none());
        assert_eq!(table.allocated_chunk_count(), 1);
    }

    #[test]
    fn resize_eagerly_allocates_every_logical_metadata_chunk() {
        let mut table = SlotTable::new();
        table.resize(LOGICAL_PAGE_COUNT).unwrap();
        assert_eq!(table.allocated_chunk_count(), LOGICAL_PAGE_COUNT.div_ceil(ENTRIES_PER_CHUNK));
    }
}
