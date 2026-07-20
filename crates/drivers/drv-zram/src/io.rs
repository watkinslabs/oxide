use alloc::vec;

use block::{BlockDevice, BlockError, BlockOp, BlockRequest, KResult};

use crate::state::{Compression, CompressionConfig, Slot, State, Zram, NOTIFY_FREE_PER_DISCARDED_PAGE, PRIMARY_COMPRESSION_PRIORITY, ZRAM_BLOCK_SIZE, PAGE_BYTES};

/// Ensures every block transaction returns detached zspages only after its
/// State guard has dropped, including all validation and I/O error exits.
struct RetireDrain<'a>(&'a Zram);
impl Drop for RetireDrain<'_> {
    fn drop(&mut self) { let _ = self.0.drain_retired_zspages(); }
}

/// Linux's ZRAM_SAME payload is one native unsigned-long word repeated across
/// the page, not one repeated byte.  Pages supplied by the block layer have a
/// whole-page length, so chunking cannot leave a tail on supported targets.
/// # C: O(PMM page / native word width)
fn same_filled_word(page: &[u8]) -> Option<usize> {
    const WORD_BYTES: usize = core::mem::size_of::<usize>();
    let mut words = page.chunks_exact(WORD_BYTES);
    let first = native_word(words.next()?);
    if words.all(|word| native_word(word) == first) { Some(first) }
    else { None }
}

/// Decode one exact native-word chunk without alignment or aliasing casts.
/// # C: O(native word width)
fn native_word(chunk: &[u8]) -> usize {
    let mut bytes = [0; core::mem::size_of::<usize>()];
    bytes.copy_from_slice(chunk);
    usize::from_ne_bytes(bytes)
}

/// Materialize the exact Linux native-word SAME representation.
/// # C: O(PMM page / native word width)
fn fill_same_word(page: &mut [u8], word: usize) {
    let bytes = word.to_ne_bytes();
    for chunk in page.chunks_exact_mut(bytes.len()) { chunk.copy_from_slice(&bytes); }
}

pub(super) fn decode_packed(config: &CompressionConfig, bytes: &[u8], page: &mut [u8]) -> KResult<()> {
    config.decompress(bytes, page)
}

pub(super) fn read_slot(state: &State, slot: &Slot, page: &mut [u8]) -> KResult<()> {
    match slot {
        Slot::Empty => page.fill(0),
        Slot::Same(word) => fill_same_word(page, *word),
        Slot::Raw { handle, .. } => {
            if handle.len() != page.len() { return Err(BlockError::Eio); }
            state.pool.read_into(*handle, page)?;
        }
        Slot::Packed { algorithm, handle, priority } => {
            let mut bytes = vec![0; handle.len()];
            state.pool.read_into(*handle, &mut bytes)?;
            let config = state.compression_config(*priority)?;
            if config.algorithm != *algorithm { return Err(BlockError::Eio); }
            decode_packed(config, &bytes, page)?;
        }
        Slot::Writeback { data, .. } => return read_slot(state, data, page),
        Slot::Backed { .. } | Slot::Loading { .. } => return Err(BlockError::Eio),
    }
    Ok(())
}

pub(super) fn encode_slot(_zram: &Zram, state: &mut State, page: &[u8], config: &CompressionConfig, priority: u8) -> KResult<Slot> {
    if let Some(word) = same_filled_word(page) { Ok(Slot::Same(word)) }
    else {
        let packed = config.compress(page)?;
        if packed.len() < crate::zsmalloc::huge_class_size() { Ok(Slot::Packed { algorithm: config.algorithm, handle: state.pool.alloc(&packed)?, priority }) }
        else { Ok(Slot::Raw { handle: state.pool.alloc(page)?, incompressible: false, priority }) }
    }
}

/// Encoded data prepared without zram State serialization. A PMM reservation
/// is deliberately not part of this value: it is obtained only after the
/// relevant slot generation has been observed.
enum PreparedSlot {
    Same(usize),
    Packed { algorithm: Compression, bytes: alloc::vec::Vec<u8>, priority: u8 },
    Raw { bytes: alloc::vec::Vec<u8>, priority: u8 },
}

impl PreparedSlot {
    fn object_bytes(&self) -> Option<&[u8]> {
        match self { Self::Packed { bytes, .. } | Self::Raw { bytes, .. } => Some(bytes), Self::Same(_) => None }
    }
    fn attach(self, handle: crate::zsmalloc::Handle) -> Slot {
        match self {
            Self::Packed { algorithm, priority, .. } => Slot::Packed { algorithm, handle, priority },
            Self::Raw { priority, .. } => Slot::Raw { handle, incompressible: false, priority },
            Self::Same(_) => unreachable!(),
        }
    }
}

/// Compress a page before taking the State lock. # C: O(page bytes)
fn prepare_slot(_zram: &Zram, page: &[u8], config: &CompressionConfig, priority: u8) -> KResult<PreparedSlot> {
    if let Some(word) = same_filled_word(page) { return Ok(PreparedSlot::Same(word)); }
    let packed = config.compress(page)?;
    if packed.len() < crate::zsmalloc::huge_class_size() { Ok(PreparedSlot::Packed { algorithm: config.algorithm, bytes: packed, priority }) }
    else { Ok(PreparedSlot::Raw { bytes: page.to_vec(), priority }) }
}

pub(super) fn free_slot_storage(state: &mut State, slot: &Slot) -> KResult<()> {
    match slot {
        Slot::Packed { handle, .. } | Slot::Raw { handle, .. } => state.pool.free(*handle),
        Slot::Writeback { data, .. } => free_slot_storage(state, data),
        Slot::Empty | Slot::Same(_) | Slot::Backed { .. } | Slot::Loading { .. } => Ok(()),
    }
}

fn write_slot(zram: &Zram, index: usize, page: &[u8]) -> KResult<()> {
    loop {
        let (generation, config) = {
            let state = zram.state.lock();
            (state.slots.generation(index).ok_or(BlockError::Einval)?, state.primary_algorithm.clone())
        };
        let prepared = prepare_slot(zram, page, &config, PRIMARY_COMPRESSION_PRIORITY)?;
        let plan = match prepared.object_bytes() {
            Some(bytes) => {
                let state = zram.state.lock();
                if state.slots.generation(index) != Some(generation) { continue; }
                Some(state.pool.allocation_plan(bytes.len())?)
            }
            None => None,
        };
        // PMM frame allocation is intentionally after every State lock has
        // dropped. A stale slot generation rescinds this reservation below.
        let reservation = match plan { Some(plan) => Some(plan.reserve()?), None => None };
        let mut rescind = None;
        let result = {
            let mut state = zram.state.lock();
            if state.slots.generation(index) != Some(generation) {
                rescind = reservation;
                None
            } else {
                let replacement = match prepared {
                    PreparedSlot::Same(word) => Slot::Same(word),
                    object => {
                        let bytes = object.object_bytes().expect("object prepared slot");
                        let (handle, unused) = state.pool.commit_reserved(reservation.expect("object reservation"), bytes)?;
                        rescind = unused;
                        object.attach(handle)
                    }
                };
                let is_huge = replacement.is_huge();
                if !state.account_pool_usage()? {
                    free_slot_storage(&mut state, &replacement)?;
                    state.account_pool_usage()?;
                    Some(Err(BlockError::Enomem))
                } else {
                    let old = state.slots.replace(index, replacement)?;
                    free_slot_storage(&mut state, &old)?;
                    state.account_pool_usage()?;
                    // Linux increments `huge_pages_since` for every raw
                    // store, including replacement of an existing huge slot;
                    // it is a lifetime event counter, not a transition count.
                    if is_huge { state.huge_pages_since += 1; }
                    Some(Ok(()))
                }
            }
        };
        if let Some(reservation) = rescind { reservation.rescind(); }
        if let Some(result) = result { return result; }
    }
}

/// Release only zram pages wholly covered by a discard range. Linux skips
/// partial physical-page fragments: discard exists to free memory, not to
/// perform a read/modify/recompress zeroing operation.
/// # C: O(number of wholly covered zram pages)
fn discard_full_pages(state: &mut State, offset: u64, len: u64) -> KResult<()> {
    let page_bytes = PAGE_BYTES as u64;
    let end = offset.checked_add(len).ok_or(BlockError::Einval)?;
    let first = offset / page_bytes + u64::from(offset % page_bytes != 0);
    let last = end / page_bytes;
    let first = usize::try_from(first).map_err(|_| BlockError::Einval)?;
    let last = usize::try_from(last).map_err(|_| BlockError::Einval)?;
    for index in first..last {
        crate::writeback::discard_slot(state, index)?;
        // Linux increments notify_free for every whole-page discard, whether
        // or not the slot was already empty.
        state.notify_free += NOTIFY_FREE_PER_DISCARDED_PAGE;
    }
    Ok(())
}

impl BlockDevice for Zram {
    fn block_size(&self) -> u32 { ZRAM_BLOCK_SIZE }

    /// Zram accepts block-layer discard requests and releases each complete
    /// logical page from its compressed backing store. Advertise that fact
    /// through the generic queue contract.
    fn supports_discard(&self) -> bool { true }

    fn queue_limits(&self) -> KResult<block::QueueLimits> {
        let page_bytes = u32::try_from(hal::PAGE_SIZE_BYTES).map_err(|_| BlockError::Einval)?;
        // Linux advertises write-zeroes only when its logical block size is
        // one zram page. This driver uses 512-byte logical sectors, so the
        // queue truthfully leaves the native maximum at zero even though the
        // request path accepts it as a discard operation.
        block::QueueLimits::new(ZRAM_BLOCK_SIZE, page_bytes, page_bytes, page_bytes)
    }

    fn capacity_blocks(&self) -> u64 { self.state.lock().size / ZRAM_BLOCK_SIZE as u64 }

    fn submit_sync(&self, request: &mut BlockRequest) -> KResult<()> {
        let _retire = RetireDrain(self);
        let len = (request.len_blocks as u64).checked_mul(ZRAM_BLOCK_SIZE as u64).ok_or(BlockError::Einval)?;
        let offset = request.start_block.checked_mul(ZRAM_BLOCK_SIZE as u64).ok_or(BlockError::Einval)?;
        let mut state = self.state.lock();
        if state.size == 0 || offset.checked_add(len).filter(|end| *end <= state.size).is_none() {
            state.invalid_io += 1;
            return Err(BlockError::Eio);
        }
        if request.op == BlockOp::Flush || len == 0 { return Ok(()); }
        let buffer_len = usize::try_from(len).map_err(|_| BlockError::Einval)?;
        if matches!(request.op, BlockOp::Read | BlockOp::Write) && request.buffer.len() != buffer_len {
            return Err(BlockError::Einval);
        }
        if matches!(request.op, BlockOp::Discard | BlockOp::WriteZeroes { .. }) {
            discard_full_pages(&mut state, offset, len)?;
            state.writes += 1;
            return Ok(());
        }
        let first = (offset / PAGE_BYTES as u64) as usize;
        let last = ((offset + len - 1) / PAGE_BYTES as u64) as usize;
        for index in first..=last {
            drop(state);
            if let Err(error) = crate::writeback::ensure_resident(self, index) {
                let mut state = self.state.lock();
                state.failed_reads += 1;
                return Err(error);
            }
            state = self.state.lock();
            // Untouched logical pages read as zero.  Do not allocate their
            // metadata solely to remember a read timestamp: large zram
            // disks must retain sparse physical memory use until data exists.
            if request.op != BlockOp::Read || !matches!(state.slots.get(index), Some(Slot::Empty)) {
                state.slots.set_idle(index, false)?;
                state.slots.set_last_access_ns(index, crate::state::monotonic_ns())?;
            }
            let page_start = index as u64 * PAGE_BYTES as u64;
            let start = offset.max(page_start);
            let end = (offset + len).min(page_start + PAGE_BYTES as u64);
            let mut page = vec![0; PAGE_BYTES];
            if let Err(error) = read_slot(&state, state.slots.get(index).ok_or(BlockError::Einval)?, &mut page) {
                state.failed_reads += 1;
                return Err(error);
            }
            let request_range = (start - offset) as usize..(end - offset) as usize;
            let page_range = (start - page_start) as usize..(end - page_start) as usize;
            match request.op {
                BlockOp::Read => request.buffer[request_range].copy_from_slice(&page[page_range]),
                BlockOp::Write => {
                    page[page_range].copy_from_slice(&request.buffer[request_range]);
                    drop(state);
                    let write_result = write_slot(self, index, &page);
                    state = self.state.lock();
                    if let Err(error) = write_result {
                        state.failed_writes += 1;
                        return Err(error);
                    }
                }
                BlockOp::WriteZeroes { .. } => unreachable!(),
                BlockOp::Discard => unreachable!(),
                BlockOp::Flush => unreachable!(),
            }
        }
        match request.op {
            BlockOp::Read => state.reads += 1,
            BlockOp::Write | BlockOp::WriteZeroes { .. } | BlockOp::Discard => state.writes += 1,
            BlockOp::Flush => {}
        }
        Ok(())
    }

    fn flush(&self) -> KResult<()> { Ok(()) }

    fn swap_slot_free_notify(&self, start_block: u64, len_blocks: u32) -> KResult<()> {
        let _retire = RetireDrain(self);
        let offset = start_block.checked_mul(ZRAM_BLOCK_SIZE as u64).ok_or(BlockError::Einval)?;
        let len = len_blocks as u64 * ZRAM_BLOCK_SIZE as u64;
        if offset % PAGE_BYTES as u64 != 0 || len == 0 || len % PAGE_BYTES as u64 != 0 { return Err(BlockError::Einval); }
        let mut state = self.state.lock();
        if state.size == 0 || offset.checked_add(len).filter(|end| *end <= state.size).is_none() {
            state.invalid_io += 1;
            return Err(BlockError::Eio);
        }
        let first = (offset / PAGE_BYTES as u64) as usize;
        let count = (len / PAGE_BYTES as u64) as usize;
        for index in first..first + count {
            if !crate::writeback::discard_slot(&mut state, index)? { state.miss_free += 1; }
        }
        state.notify_free += count as u64;
        Ok(())
    }
}
