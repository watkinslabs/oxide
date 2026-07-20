//! Core zram block, compaction, and sizing contracts.

use super::*;

#[test]
fn advertises_its_discard_operation() {
    let zram = Zram::new();
    assert!(zram.supports_discard());
}

#[test]
fn write_zeroes_uses_linux_zram_full_page_discard_rules() {
    let zram = Zram::new();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let blocks = PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE;
    let mut data = alloc::vec![WRITE_ZEROES_SECOND_HALF_BYTE; PAGE_BYTES];
    let first_half = PAGE_BYTES / 2;
    data[..first_half].fill(WRITE_ZEROES_FIRST_HALF_BYTE);
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_DEVICE_BLOCK, blocks, data)).unwrap();
    let half_blocks = blocks / 2;
    zram.submit_sync(&mut BlockRequest::new_write_zeroes(half_blocks as u64, half_blocks, true)).unwrap();
    let mut read = BlockRequest::new_read(FIRST_DEVICE_BLOCK, blocks, ZRAM_BLOCK_SIZE);
    zram.submit_sync(&mut read).unwrap();
    assert!(read.buffer[..first_half].iter().all(|byte| *byte == WRITE_ZEROES_FIRST_HALF_BYTE));
    assert!(read.buffer[first_half..].iter().all(|byte| *byte == WRITE_ZEROES_SECOND_HALF_BYTE));
    zram.submit_sync(&mut BlockRequest::new_write_zeroes(FIRST_DEVICE_BLOCK, blocks, false)).unwrap();
    zram.submit_sync(&mut read).unwrap();
    assert!(read.buffer.iter().all(|byte| *byte == ZERO_DATA_BYTE));
    assert_eq!(zram.queue_limits().unwrap().max_write_zeroes_sectors(), 0);
}

#[test]
fn compressed_page_roundtrips() {
    let zram = Zram::new();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let mut data = alloc::vec![ZERO_DATA_BYTE; PAGE_BYTES];
    for (index, byte) in data.iter_mut().enumerate() { *byte = index as u8; }
    let mut write = BlockRequest::new_write(FIRST_DEVICE_BLOCK, PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE, data.clone());
    zram.submit_sync(&mut write).unwrap();
    let mut read = BlockRequest::new_read(FIRST_DEVICE_BLOCK, PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE, ZRAM_BLOCK_SIZE);
    zram.submit_sync(&mut read).unwrap();
    assert_eq!(read.buffer, data);
    assert!(zram.stats().mem_used >= MINIMUM_NONZERO_MEMORY_USAGE);
}

#[test]
fn compact_relocates_zspage_objects_without_rewriting_zram_slot_handles() {
    let zram = Zram::new();
    zram.set_disksize(PAGE_BYTES as u64 * COMPACTION_OBJECT_COUNT as u64).unwrap();
    let (expected_first, expected_last);
    {
        let mut state = zram.state.lock();
        let mut handles = alloc::vec::Vec::new();
        for index in 0..COMPACTION_OBJECT_COUNT {
            let byte = if index == COMPACTION_LAST_INDEX { COMPACTION_LAST_BYTE } else { COMPACTION_FIRST_BYTE };
            handles.push(state.pool.alloc(&alloc::vec![byte; COMPACTION_OBJECT_BYTES]).unwrap());
        }
        let first_live_handle = handles[COMPACTION_FIRST_LIVE_INDEX];
        let last_handle = handles[COMPACTION_LAST_INDEX];
        expected_first = first_live_handle;
        expected_last = last_handle;
        state.pool.free(handles[COMPACTION_FREED_INDEX]).unwrap();
        for (index, handle) in handles.into_iter().enumerate().skip(COMPACTION_FIRST_LIVE_INDEX) {
            state.slots.replace(index, Slot::Raw { handle, incompressible: false, priority: crate::state::PRIMARY_COMPRESSION_PRIORITY }).unwrap();
        }
        assert_eq!(state.pool.page_count(), COMPACTION_INITIAL_PAGE_COUNT);
        assert!(matches!(state.slots.get(COMPACTION_FIRST_LIVE_INDEX), Some(Slot::Raw { handle, .. }) if *handle == first_live_handle));
        assert!(matches!(state.slots.get(COMPACTION_LAST_INDEX), Some(Slot::Raw { handle, .. }) if *handle == last_handle));
    }
    zram.compact().unwrap();
    let state = zram.state.lock();
    assert_eq!(state.pool.page_count(), COMPACTION_FINAL_PAGE_COUNT);
    let first_handle = match state.slots.get(COMPACTION_FIRST_LIVE_INDEX).unwrap() { Slot::Raw { handle, .. } => *handle, _ => unreachable!() };
    let last_handle = match state.slots.get(COMPACTION_LAST_INDEX).unwrap() { Slot::Raw { handle, .. } => *handle, _ => unreachable!() };
    assert_eq!(first_handle, expected_first);
    assert_eq!(last_handle, expected_last);
    let mut first = alloc::vec![ZERO_DATA_BYTE; COMPACTION_OBJECT_BYTES];
    let mut last = alloc::vec![ZERO_DATA_BYTE; COMPACTION_OBJECT_BYTES];
    crate::io::read_slot(&state, state.slots.get(COMPACTION_FIRST_LIVE_INDEX).unwrap(), &mut first).unwrap();
    crate::io::read_slot(&state, state.slots.get(COMPACTION_LAST_INDEX).unwrap(), &mut last).unwrap();
    assert_eq!(first, alloc::vec![COMPACTION_FIRST_BYTE; COMPACTION_OBJECT_BYTES]);
    assert_eq!(last, alloc::vec![COMPACTION_LAST_BYTE; COMPACTION_OBJECT_BYTES]);
    assert!(state.pool.read_into(first_handle, &mut first).is_ok());
    assert!(state.pool.read_into(last_handle, &mut last).is_ok());
    drop(state);
    assert_eq!(zram.stats().pages_compacted, COMPACTION_RELEASED_PAGE_COUNT);
}

#[test]
fn sysfs_size_suffixes_use_binary_units() {
    let zram = Zram::new();
    zram.set_mem_limit_text(TWO_MEBIBYTE_TEXT).unwrap();
    zram.set_disksize_text(ONE_MEBIBYTE_TEXT).unwrap();
    let stats = zram.stats();
    assert_eq!(stats.disksize, MEBIBYTE_BYTES);
    assert_eq!(stats.mem_limit, TWO_MEBIBYTES * MEBIBYTE_BYTES);
}

#[test]
fn linux_sysfs_sizes_round_up_to_allocator_pages() {
    let zram = Zram::new();
    zram.set_mem_limit(IMPOSSIBLE_MEMORY_LIMIT_BYTES).unwrap();
    zram.set_disksize((PAGE_BYTES - 1) as u64).unwrap();
    let stats = zram.stats();
    assert_eq!(stats.disksize, ZRAM_PAGE_BYTES);
    assert_eq!(stats.mem_limit, ZRAM_PAGE_BYTES);
}

#[test]
fn generator_sized_device_initializes_without_data_page_allocation() {
    let zram = Zram::new();
    zram.set_disksize_text(GENERATOR_DISKSIZE_TEXT).unwrap();
    let stats = zram.stats();
    assert_eq!(stats.disksize, GENERATOR_DISKSIZE_GIB * GIBIBYTE_BYTES);
    assert_eq!(stats.mem_used, EMPTY_MEMORY_USAGE);
}

#[test]
fn untouched_generator_sized_page_read_uses_eager_linux_metadata() {
    let zram = Zram::new();
    zram.set_disksize_text(GENERATOR_DISKSIZE_TEXT).unwrap();
    let blocks_per_page = PAGE_BYTES as u64 / ZRAM_BLOCK_SIZE as u64;
    let last_page = zram.capacity_blocks() - blocks_per_page;
    let mut read = BlockRequest::new_read(last_page, blocks_per_page as u32, ZRAM_BLOCK_SIZE);
    zram.submit_sync(&mut read).unwrap();
    assert_eq!(read.buffer, alloc::vec![ZERO_DATA_BYTE; PAGE_BYTES]);
    assert!(zram.state.lock().slots.allocated_chunk_count() > 0);
}
