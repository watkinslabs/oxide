use super::*;

/// Store one complete anonymous page and return its canonical PTE identity.
/// The slot remains reserved while I/O runs, so no concurrent page-out can use
/// it; only successful writes become visible as `Used`.
/// # C: O(area slots + page I/O)
pub fn store_page(page: &[u8], memcg: u64) -> Result<SwapEntry> {
    if page.len() != hal::PAGE_SIZE_BYTES as usize { return Err(SwapError::Inval); }
    let (kind, offset, device, start_block, len_blocks) = {
        let mut areas = AREAS.lock();
        let priority = areas.areas.iter().flatten()
            .filter(|area| !area.draining && area.has_free_slot())
            .map(|area| area.priority).max().ok_or(SwapError::NoSpace)?;
        let start = areas.rotation_start(priority);
        let kind = (0..SWAP_AREA_COUNT).map(|delta| (start + delta) % SWAP_AREA_COUNT)
            .find(|kind| areas.areas[*kind].as_ref().is_some_and(|area|
                !area.draining && area.priority == priority && area.has_free_slot()))
            .ok_or(SwapError::NoSpace)?;
        areas.advance_rotation(priority, kind)?;
        let area = areas.areas[kind].as_mut().ok_or(SwapError::NoSuchArea)?;
        let offset = area.next_free_slot().ok_or(SwapError::NoSpace)?;
        area.set_slot(offset, Slot::Writing)?;
        (kind as u8, offset as u64, area.device.clone(), area.page_block(offset as u64)?, area.blocks_per_page)
    };
    let mut request = BlockRequest::new_write(start_block, len_blocks, page.to_vec());
    if let Err(error) = device.submit_sync(&mut request) {
        let mut areas = AREAS.lock();
        if let Some(area) = areas.areas.get_mut(kind as usize).and_then(Option::as_mut) {
            if area.slot(offset as usize) == Some(Slot::Writing) { area.set_slot(offset as usize, Slot::Free)?; }
        }
        return Err(error.into());
    }
    let mut areas = AREAS.lock();
    let area = areas.areas.get_mut(kind as usize).and_then(Option::as_mut).ok_or(SwapError::NoSuchArea)?;
    if area.slot(offset as usize) != Some(Slot::Writing) { return Err(SwapError::Io); }
    area.set_slot(offset as usize, Slot::Used { refs: INITIAL_SLOT_PTE_REFS, memcg })?;
    SwapEntry::new(kind, offset).ok_or(SwapError::Inval)
}
/// Read a complete swapped page without releasing its slot. The fault handler
/// frees it only after it has installed the replacement present PTE.
/// # C: O(page I/O)
pub fn load_page(entry: SwapEntry, page: &mut [u8]) -> Result<()> {
    if page.len() != hal::PAGE_SIZE_BYTES as usize { return Err(SwapError::Inval); }
    let (device, start_block, len_blocks) = {
        let areas = AREAS.lock();
        let area = areas.areas.get(entry.kind() as usize).and_then(Option::as_ref).ok_or(SwapError::NoSuchArea)?;
        if !matches!(area.slot(entry.offset() as usize), Some(Slot::Used { .. })) { return Err(SwapError::Inval); }
        (area.device.clone(), area.page_block(entry.offset())?, area.blocks_per_page)
    };
    let mut request = BlockRequest::new_read(start_block, len_blocks, device.block_size());
    device.submit_sync(&mut request).map_err(SwapError::from)?;
    if request.buffer.len() != page.len() { return Err(SwapError::Io); }
    page.copy_from_slice(&request.buffer);
    Ok(())
}

/// Add one PTE reference to a shared swapped page. Fork/pageout uses this for
/// every mapping after the first; the slot stays live until every PTE is gone.
/// # C: O(1)
pub fn retain_page(entry: SwapEntry) -> Result<()> {
    let mut areas = AREAS.lock();
    let area = areas.areas.get_mut(entry.kind() as usize).and_then(Option::as_mut).ok_or(SwapError::NoSuchArea)?;
    // A fork must not publish a new child PTE into an area swapoff has made
    // unavailable.  The clone path handles this Busy result by restoring the
    // parent leaf and retrying from RAM, preserving the Linux drain contract.
    if area.draining { return Err(SwapError::Busy); }
    match area.slot(entry.offset() as usize) {
        Some(Slot::Used { refs, memcg }) => {
            area.set_slot(entry.offset() as usize,
                Slot::Used { refs: refs.checked_add(1).ok_or(SwapError::NoSpace)?, memcg })
        }
        _ => Err(SwapError::Inval),
    }
}

/// Number of live swap PTEs naming `entry`.  This is deliberately separate
/// from block I/O and slot-state ownership: it is the swap analogue of a RAM
/// frame's `PageMeta::mapcount`, and is the sole source for shared-swap PSS.
/// # C: O(1)
pub fn pte_mapcount(entry: SwapEntry) -> Result<u32> {
    let areas = AREAS.lock();
    let area = areas.areas.get(entry.kind() as usize).and_then(Option::as_ref).ok_or(SwapError::NoSuchArea)?;
    match area.slot(entry.offset() as usize) {
        Some(Slot::Used { refs, .. }) => Ok(refs),
        _ => Err(SwapError::Inval),
    }
}

/// Drop one PTE reference after its data has been made resident again or the
/// swapped PTE is unmapped. The slot is reusable only after its final PTE.
/// # C: O(1)
pub fn free_page(entry: SwapEntry) -> Result<()> {
    let release = {
        let mut areas = AREAS.lock();
        let area = areas.areas.get_mut(entry.kind() as usize).and_then(Option::as_mut).ok_or(SwapError::NoSuchArea)?;
        match area.slot(entry.offset() as usize) {
            Some(Slot::Used { refs: INITIAL_SLOT_PTE_REFS, memcg }) => {
                area.set_slot(entry.offset() as usize, Slot::Releasing)?;
                Some((area.device.clone(), area.page_block(entry.offset())?, area.blocks_per_page, area.discard, memcg))
            }
            Some(Slot::Used { refs, memcg }) => {
                area.set_slot(entry.offset() as usize, Slot::Used { refs: refs - 1, memcg })?;
                None
            }
            _ => return Err(SwapError::Inval),
        }
    };
    let Some((device, start_block, len_blocks, policy, memcg)) = release else { return Ok(()); };
    let result = device.swap_slot_free_notify(start_block, len_blocks).map_err(SwapError::from);
    let mut areas = AREAS.lock();
    let area = areas.areas.get_mut(entry.kind() as usize).and_then(Option::as_mut).ok_or(SwapError::NoSuchArea)?;
    if area.slot(entry.offset() as usize) != Some(Slot::Releasing) { return Err(SwapError::Io); }
    area.set_slot(entry.offset() as usize, Slot::Free)?;
    cgroup::uncharge_swap(memcg, hal::PAGE_SIZE_BYTES);
    drop(areas);
    if policy.pages() { let _ = discard::discard_range(device.as_ref(), start_block, len_blocks); }
    result
}

/// Cgroup owning the anonymous contents of `entry`. The charge remains with
/// that memcg when a process moves or fork adds PTE references. # C: O(1)
pub fn memcg(entry: SwapEntry) -> Result<u64> {
    let areas = AREAS.lock();
    let area = areas.areas.get(entry.kind() as usize).and_then(Option::as_ref).ok_or(SwapError::NoSuchArea)?;
    match area.slot(entry.offset() as usize) {
        Some(Slot::Used { memcg, .. }) => Ok(memcg),
        _ => Err(SwapError::Inval),
    }
}

/// Snapshot active swap areas for `/proc/swaps`, `sysinfo`, and `meminfo`.
/// # C: O(areas + slots)
pub fn snapshot() -> Vec<AreaInfo> {
    let areas = AREAS.lock();
    areas.areas.iter().enumerate().filter_map(|(kind, area)| area.as_ref().map(|area| AreaInfo {
        name: area.name.clone(), kind: kind as u8,
        display_name: area.display_name.clone(), backing: area.backing,
        pages: (area.slot_count - area.reserved.len() - FIRST_DATA_PAGE as usize) as u64,
        used_pages: area.used_slots(),
        priority: area.priority,
    })).collect()
}

/// Find the active area by backing block device name.
/// # C: O(areas)
pub fn kind_for_name(name: &str) -> Option<u8> {
    AREAS.lock().areas.iter().position(|area| area.as_ref().is_some_and(|area| area.name == name)).map(|kind| kind as u8)
}
