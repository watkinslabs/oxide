use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::vec;

use block::{BlockError, BlockRequest, KResult};

use crate::state::{writeback_units_per_page, BackingFormat, CompressionConfig, Slot, State, Zram, PRIMARY_COMPRESSION_PRIORITY, PAGE_BYTES};

mod batch;
use batch::Batch;
mod recompress;
pub(crate) use recompress::recompress_text;

struct WritebackWork {
    index: usize,
    backing_page: usize,
    format: BackingFormat,
    bytes: Vec<u8>,
    disk: alloc::sync::Arc<block::registry::Disk>,
    blocks_per_page: u32,
    writeback_units: u64,
    budget_reserved: bool,
}

#[derive(Copy, Clone)]
pub(super) enum Selector { Idle, Huge, HugeIdle, Incompressible }

/// `recompress` accepts only the three Linux post-processing modes.  The
/// writeback-only `incompressible` mode is deliberately not part of this ABI.
pub(super) fn recompress_selector_from_text(text: &str) -> Option<Selector> {
    match text {
        "idle" => Some(Selector::Idle),
        "huge" => Some(Selector::Huge),
        "huge_idle" => Some(Selector::HugeIdle),
        _ => None,
    }
}

fn selector_from_text(text: &str) -> Option<Selector> {
    match text {
        "idle" => Some(Selector::Idle),
        "huge" => Some(Selector::Huge),
        "huge_idle" => Some(Selector::HugeIdle),
        "incompressible" => Some(Selector::Incompressible),
        _ => None,
    }
}

pub(super) fn selected(state: &State, index: usize, selector: Selector) -> bool {
    let Some(slot) = state.slots.get(index) else { return false; };
    if !matches!(slot, Slot::Packed { .. } | Slot::Raw { .. }) { return false; }
    let idle = state.slots.idle(index).unwrap_or(false);
    let huge = slot.is_huge();
    match selector {
        Selector::Idle => idle,
        Selector::Huge => huge,
        Selector::Incompressible => slot.is_incompressible(),
        Selector::HugeIdle => huge && idle,
    }
}

fn writeback_selected(zram: &Zram, selector: Selector) -> KResult<()> {
    let pages = {
        let state = zram.state.lock();
        (0..state.slots.len()).filter(|index| selected(&state, *index, selector)).collect::<Vec<_>>()
    };
    writeback_pages(zram, pages)
}

fn parse_page_index(value: &str, page_count: u64) -> KResult<(usize, usize)> {
    let index = value.parse::<u64>().map_err(|_| BlockError::Einval)?;
    if index >= page_count { return Err(BlockError::Einval); }
    let index = usize::try_from(index).map_err(|_| BlockError::Einval)?;
    Ok((index, index))
}

fn parse_page_indexes(value: &str, page_count: u64) -> KResult<(usize, usize)> {
    let (first, last) = value.split_once('-').ok_or(BlockError::Einval)?;
    if last.contains('-') { return Err(BlockError::Einval); }
    let first = first.parse::<u64>().map_err(|_| BlockError::Einval)?;
    let last = last.parse::<u64>().map_err(|_| BlockError::Einval)?;
    if first > last || last >= page_count { return Err(BlockError::Einval); }
    Ok((usize::try_from(first).map_err(|_| BlockError::Einval)?, usize::try_from(last).map_err(|_| BlockError::Einval)?))
}

/// Parse Linux `writeback` sysfs requests. Bare mode names are retained only
/// as Linux's legacy ABI; modern modes use `type=<mode>`. `page_index` selects
/// one page and `page_indexes` requires an inclusive range.
/// # C: O(zram pages × backing page I/O) for selectors
pub(super) fn writeback_text(zram: &Zram, text: &str) -> KResult<()> {
    let page_count = {
        let state = zram.state.lock();
        if state.backing.is_none() { return Err(BlockError::Enxio); }
        u64::try_from(state.slots.len()).map_err(|_| BlockError::Einval)?
    };
    for item in text.trim().split_ascii_whitespace() {
        let Some((key, value)) = item.split_once('=') else {
            let selector = selector_from_text(item).ok_or(BlockError::Einval)?;
            return writeback_selected(zram, selector);
        };
        // Linux's `next_arg` rejects a malformed `name=value` token before
        // dispatching recognized or forward-compatible names.
        if key.is_empty() || value.is_empty() { return Err(BlockError::Einval); }
        match key {
            "type" => return writeback_selected(zram, selector_from_text(value).ok_or(BlockError::Einval)?),
            "page_index" => {
                let (first, last) = parse_page_index(value, page_count)?;
                writeback_pages(zram, first..=last)?;
            }
            "page_indexes" => {
                let (first, last) = parse_page_indexes(value, page_count)?;
                writeback_pages(zram, first..=last)?;
            }
            // Linux's `next_arg` parser ignores unknown key/value pairs.
            _ => {}
        }
    }
    Ok(())
}

/// Serialize one resident object for a backing extent. In compressed mode a
/// packed object is written byte-for-byte and its exact length stays in the
/// canonical zram slot table; raw objects retain their complete page form.
/// # C: O(PMM page)
fn backing_bytes(state: &State, slot: &Slot, compressed_writeback: bool) -> KResult<(BackingFormat, Vec<u8>)> {
    if compressed_writeback {
        if let Slot::Packed { algorithm, handle, priority } = slot {
            let mut page = vec![0; PAGE_BYTES];
            if handle.len() >= page.len() { return Err(BlockError::Eio); }
            state.pool.read_into(*handle, &mut page[..handle.len()])?;
            return Ok((BackingFormat::Packed { algorithm: *algorithm, len: handle.len(), priority: *priority }, page));
        }
    }
    let mut page = vec![0; PAGE_BYTES];
    crate::io::read_slot(state, slot, &mut page)?;
    Ok((BackingFormat::FullPage, page))
}

/// Decode a backing object using its authoritative zram-table format.
/// # C: O(PMM page)
fn decode_backing(zram: &Zram, state: &mut State, format: BackingFormat, bytes: &[u8], primary: CompressionConfig) -> KResult<Slot> {
    match format {
        BackingFormat::FullPage => crate::io::encode_slot(zram, state, bytes, &primary, PRIMARY_COMPRESSION_PRIORITY),
        BackingFormat::Packed { algorithm, len, priority } => {
            if len > bytes.len() { return Err(BlockError::Eio); }
            let packed = bytes[..len].to_vec();
            let mut decoded = vec![0; PAGE_BYTES];
            let config = state.compression_config(priority)?;
            if config.algorithm != algorithm { return Err(BlockError::Eio); }
            crate::io::decode_packed(config, &packed, &mut decoded)?;
            Ok(Slot::Packed { algorithm, handle: state.pool.alloc(&packed)?, priority })
        }
    }
}

fn submit_backing_read(disk: &block::registry::Disk, page: usize, blocks_per_page: u32, bytes: &mut [u8]) -> KResult<()> {
    let start = (page as u64).checked_mul(blocks_per_page as u64).ok_or(BlockError::Einval)?;
    let mut request = BlockRequest::new_read(start, blocks_per_page, disk.dev.block_size());
    disk.dev.submit_sync(&mut request)?;
    bytes.copy_from_slice(&request.buffer);
    Ok(())
}

/// Materialize one backed slot before normal zram I/O accesses it. The owner
/// performs the external read without holding zram's state lock; concurrent
/// users observe `Loading` and retry, never consuming an incomplete buffer.
/// # C: O(backing page I/O + compression)
pub(super) fn ensure_resident(zram: &Zram, index: usize) -> KResult<()> {
    loop {
        let work = {
            let mut state = zram.state.lock();
            match state.slots.get(index).ok_or(BlockError::Einval)? {
                Slot::Backed { page, format } => {
                    let (page, format) = (*page, *format);
                    let backing = state.backing.as_ref().ok_or(BlockError::Enxio)?;
                    let disk = backing.disk.clone();
                    let blocks_per_page = backing.blocks_per_page;
                    state.slots.replace(index, Slot::Loading { page, format })?;
                    Some((page, format, disk, blocks_per_page))
                }
                Slot::Loading { .. } => {
                    #[cfg(target_os = "oxide-kernel")]
                    {
                        // SAFETY: the zram state lock serializes this park
                        // with the reload owner's final-state publication.
                        unsafe { zram.loading_waiters.park(); }
                    }
                    None
                }
                _ => return Ok(()),
            }
        };
        let Some((page, format, disk, blocks_per_page)) = work else {
            #[cfg(target_os = "oxide-kernel")]
            {
                // SAFETY: the waiter was published while holding the zram
                // state lock and that lock has now been released.
                unsafe { sched::live::schedule::schedule(); }
                continue;
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(BlockError::Eagain);
        };
        let mut bytes = vec![0; PAGE_BYTES];
        let result = submit_backing_read(&disk, page, blocks_per_page, &mut bytes);
        let mut state = zram.state.lock();
        if !matches!(state.slots.get(index), Some(Slot::Loading { page: current, format: current_format }) if *current == page && *current_format == format) {
            drop(state);
            #[cfg(target_os = "oxide-kernel")]
            zram.loading_waiters.wake_all();
            continue;
        }
        let outcome = match result {
            Ok(()) => {
                let primary = state.primary_algorithm.clone();
                let replacement = match decode_backing(zram, &mut state, format, &bytes, primary) {
                    Ok(replacement) => Ok(replacement),
                    Err(error) => {
                        state.slots.replace(index, Slot::Backed { page, format })?;
                        Err(error)
                    }
                };
                match replacement {
                    Err(error) => Err(error),
                    Ok(replacement) => match state.account_pool_usage()? {
                        false => {
                            crate::io::free_slot_storage(&mut state, &replacement)?;
                            state.account_pool_usage()?;
                            state.slots.replace(index, Slot::Backed { page, format })?;
                            Err(BlockError::Enomem)
                        }
                        true => {
                            state.slots.replace(index, replacement)?;
                            state.account_pool_usage()?;
                            state.backing_reads += 1;
                            let backing = state.backing.as_mut().expect("backing held while slot loads");
                            backing.extents[page] = false;
                            Ok(())
                        }
                    },
                }
            }
            Err(error) => {
                state.slots.replace(index, Slot::Backed { page, format })?;
                Err(error)
            }
        };
        drop(state);
        #[cfg(target_os = "oxide-kernel")]
        zram.loading_waiters.wake_all();
        return outcome;
    }
}

fn free_extent(state: &mut State, page: usize) {
    if let Some(backing) = state.backing.as_mut() {
        if page < backing.extents.len() { backing.extents[page] = false; }
    }
}

/// Remove a zram slot and return any backing extent it owns. A pending I/O
/// completion sees the changed slot and cannot resurrect discarded data.
/// # C: O(1)
pub(super) fn discard_slot(state: &mut State, index: usize) -> KResult<bool> {
    let slot = state.slots.replace(index, Slot::Empty)?;
    match slot {
        Slot::Empty => Ok(false),
        Slot::Backed { page, .. } | Slot::Loading { page, .. } => {
            free_extent(state, page);
            Ok(true)
        }
        Slot::Writeback { page, data } => {
            crate::io::free_slot_storage(state, &data)?;
            state.account_pool_usage()?;
            free_extent(state, page);
            Ok(true)
        }
        slot => {
            crate::io::free_slot_storage(state, &slot)?;
            state.account_pool_usage()?;
            Ok(true)
        }
    }
}

/// Persist one resident zram page and release its RAM object on successful
/// completion. A concurrent overwrite wins: it remains resident and the now
/// stale backing extent is returned to the allocator.
/// # C: O(backing page I/O + compression)
fn begin_writeback(zram: &Zram, index: usize) -> KResult<WritebackWork> {
    let writeback_units = writeback_units_per_page();
    let work = {
        let mut state = zram.state.lock();
        let slot = state.slots.get(index).ok_or(BlockError::Einval)?;
        if !matches!(slot, Slot::Packed { .. } | Slot::Raw { .. }) { return Err(BlockError::Ebusy); }
        let available_writeback = state.writeback_limit.saturating_sub(state.writeback_reserved);
        if state.writeback_limit_enable && available_writeback < writeback_units { return Err(BlockError::Eio); }
        let compressed_writeback = state.compressed_writeback;
        let (format, bytes) = backing_bytes(&state, slot, compressed_writeback)?;
        let Some(backing) = state.backing.as_ref() else {
            return Err(BlockError::Enxio);
        };
        let Some(backing_page) = backing.extents.iter().position(|used| !*used) else {
            return Err(BlockError::Enospc);
        };
        let disk = backing.disk.clone();
        let blocks_per_page = backing.blocks_per_page;
        let budget_reserved = state.writeback_limit_enable;
        // Validate every fallible accounting transition before claiming either
        // the backing extent or the slot.  A rejected writeback must leave the
        // resident object and extent map exactly as it found them.
        let reserved_after = if budget_reserved {
            state.writeback_reserved.checked_add(writeback_units).ok_or(BlockError::Eio)?
        } else { state.writeback_reserved };
        let active_after = state.active_writebacks.checked_add(1).ok_or(BlockError::Enomem)?;
        let slot = state.slots.replace(index, Slot::Empty)?;
        state.backing.as_mut().expect("backing checked above").extents[backing_page] = true;
        state.writeback_reserved = reserved_after;
        state.active_writebacks = active_after;
        state.slots.replace(index, Slot::Writeback { page: backing_page, data: Box::new(slot) })?;
        WritebackWork { index, backing_page, format, bytes, disk, blocks_per_page, writeback_units, budget_reserved }
    };
    Ok(work)
}

fn finish_writeback(zram: &Zram, work: WritebackWork, result: KResult<()>) -> KResult<()> {
    let mut state = zram.state.lock();
    if work.budget_reserved {
        let Some(reserved) = state.writeback_reserved.checked_sub(work.writeback_units) else {
            return Err(BlockError::Eio);
        };
        state.writeback_reserved = reserved;
    }
    let Some(active) = state.active_writebacks.checked_sub(1) else { return Err(BlockError::Eio); };
    state.active_writebacks = active;
    let result = if work.budget_reserved && result.is_ok() {
        match state.writeback_limit.checked_sub(work.writeback_units) {
            Some(limit) => {
                state.writeback_limit = limit;
                result
            }
            None => Err(BlockError::Eio),
        }
    } else { result };
    let slot = state.slots.replace(work.index, Slot::Empty)?;
    let outcome = match (slot, result) {
        (Slot::Writeback { page, data }, Ok(())) if page == work.backing_page => {
            crate::io::free_slot_storage(&mut state, &data)?;
            state.account_pool_usage()?;
            state.slots.set_idle(work.index, false)?;
            state.slots.replace(work.index, Slot::Backed { page, format: work.format })?;
            state.backing_writes += 1;
            Ok(())
        }
        (Slot::Writeback { page, data }, Err(error)) if page == work.backing_page => {
            state.slots.replace(work.index, *data)?;
            free_extent(&mut state, page);
            Err(error)
        }
        (slot, result) => {
            state.slots.replace(work.index, slot)?;
            free_extent(&mut state, work.backing_page);
            result
        }
    };
    drop(state);
    #[cfg(target_os = "oxide-kernel")]
    zram.writeback_waiters.wake_all();
    outcome
}

/// Persist one resident zram page and wait for its owned block completion.
/// # C: O(backing page I/O + compression)
pub(crate) fn writeback_page(zram: &Zram, index: usize) -> KResult<()> {
    let mut work = begin_writeback(zram, index)?;
    let start = (work.backing_page as u64).checked_mul(work.blocks_per_page as u64).ok_or(BlockError::Einval)?;
    let mut request = BlockRequest::new_write(start, work.blocks_per_page, core::mem::take(&mut work.bytes));
    let disk = work.disk.clone();
    let result = disk.dev.submit_sync(&mut request);
    finish_writeback(zram, work, result)
}

/// Submit all selected pages through the canonical owned-request interface,
/// then wait until every accepted request published its canonical slot state.
/// # C: O(selected zram pages + backing page I/O)
pub(crate) fn writeback_pages(zram: &Zram, pages: impl IntoIterator<Item = usize>) -> KResult<()> {
    let batch_size = zram.state.lock().writeback_batch_size as usize;
    let mut batch = Batch::new();
    let mut submitted = 0usize;
    let mut submission_error = None;
    for index in pages {
        if submitted == batch_size {
            if let Err(error) = batch.wait() { return Err(error); }
            batch = Batch::new();
            submitted = 0;
        }
        let mut work = match begin_writeback(zram, index) {
            Ok(work) => work,
            Err(BlockError::Ebusy) => continue,
            Err(error) => {
                submission_error = Some(error);
                break;
            }
        };
        let start = match (work.backing_page as u64).checked_mul(work.blocks_per_page as u64) {
            Some(start) => start,
            None => {
                let _ = finish_writeback(zram, work, Err(BlockError::Einval));
                submission_error = Some(BlockError::Einval);
                break;
            }
        };
        let request = BlockRequest::new_write(start, work.blocks_per_page, core::mem::take(&mut work.bytes));
        let owner = zram.strong_ref();
        let joined = batch.clone();
        let disk = work.disk.clone();
        batch.reserve();
        submitted += 1;
        disk.dev.submit(request, Box::new(move |_, result| {
            let result = finish_writeback(&owner, work, result);
            joined.complete(result);
        }));
    }
    let completion_error = batch.wait();
    submission_error.map_or(completion_error, Err)
}
