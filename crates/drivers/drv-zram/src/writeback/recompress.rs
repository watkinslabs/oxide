//! Linux zram multi-compressor recompression transaction.

use alloc::vec;

use block::{BlockError, KResult};

use crate::state::{Compression, Slot, Zram, PAGE_BYTES, RECOMP_MIN_COMPRESSED_BYTES};

use super::{recompress_selector_from_text, selected};

/// `zs_huge_class_size()` equivalent for this page-sized zsmalloc-backed
/// driver. A payload at or above this boundary is raw, not recompressible.
const RECOMPRESS_HUGE_CLASS_BYTES: usize = PAGE_BYTES;

/// Parse Linux `recompress` key-value input. `type` is optional; without it
/// every resident compressed object meeting `threshold` is considered.
/// # C: O(selected zram pages × compression)
pub(crate) fn recompress_text(zram: &Zram, text: &str) -> KResult<()> {
    let mut selector = None;
    let mut priority = None;
    let mut algorithm = None;
    let mut threshold = RECOMP_MIN_COMPRESSED_BYTES;
    let mut max_pages = None;
    for item in text.split_ascii_whitespace() {
        let Some((name, value)) = item.split_once('=') else { return Err(BlockError::Einval); };
        if name.is_empty() || value.is_empty() { return Err(BlockError::Einval); }
        match name {
            "type" => selector = Some(recompress_selector_from_text(value).ok_or(BlockError::Einval)?),
            "priority" => priority = Some(value.parse::<usize>().map_err(|_| BlockError::Einval)?),
            "algo" => algorithm = Some(Compression::from_name(value).ok_or(BlockError::Einval)?),
            "threshold" => threshold = value.parse::<usize>().map_err(|_| BlockError::Einval)?,
            "max_pages" => max_pages = Some(value.parse::<u64>().map_err(|_| BlockError::Einval)?),
            _ => {}
        }
    }
    if threshold >= RECOMPRESS_HUGE_CLASS_BYTES { return Err(BlockError::Einval); }
    let mut state = zram.state.lock();
    let (secondary, secondary_priority) = match (priority, algorithm) {
        (Some(priority), None) => priority.checked_sub(1).and_then(|index|
            state.recompression_algorithms.get(index).cloned().flatten().map(|config| (config, priority as u8))),
        (None, Some(algorithm)) => state.recompression_algorithms.iter().enumerate().find_map(|(index, configured)|
            configured.as_ref().filter(|configured| configured.algorithm == algorithm).cloned().map(|config| (config, (index + 1) as u8))),
        (Some(priority), Some(algorithm)) => priority.checked_sub(1).and_then(|index|
            state.recompression_algorithms.get(index).cloned().flatten().filter(|config| config.algorithm == algorithm).map(|config| (config, priority as u8))),
        (None, None) => state.recompression_algorithms.first().cloned().flatten().map(|config| (config, 1)),
    }.ok_or(BlockError::Einval)?;
    let mut remaining = max_pages.unwrap_or(u64::MAX);
    for index in 0..state.slots.len() {
        if remaining == 0 { break; }
        if selector.is_some_and(|selector| !selected(&state, index, selector)) { continue; }
        let slot = state.slots.get(index).expect("zram slot index validated by table length");
        let old_size = slot.bytes();
        if old_size < threshold || matches!(slot, Slot::Empty | Slot::Same(_) | Slot::Backed { .. } | Slot::Loading { .. } | Slot::Writeback { .. }) { continue; }
        let mut page = vec![0; PAGE_BYTES];
        crate::io::read_slot(&state, slot, &mut page)?;
        state.slots.set_idle(index, false)?;
        let replacement = crate::io::encode_slot(&mut state, &page, &secondary, secondary_priority)?;
        remaining -= 1;
        if replacement.bytes() >= old_size {
            let incompressible = replacement.is_huge();
            crate::io::free_slot_storage(&mut state, &replacement)?;
            if incompressible { state.slots.get_mut(index).expect("zram slot index validated by table length").mark_incompressible(); }
            continue;
        }
        let old = state.slots.replace(index, replacement)?;
        crate::io::free_slot_storage(&mut state, &old)?;
        state.account_pool_usage()?;
    }
    Ok(())
}
