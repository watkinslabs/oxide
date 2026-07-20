use block::{BlockDevice, BlockRequest};

use crate::Zram;
use crate::state::{Compression, PAGE_BYTES, Slot};

const DEFLATE_ALGORITHM: &str = "deflate";
const LZO_ALGORITHM: &str = "lzo";
const DEFLATE_PRIORITY_ONE: &str = "algo=deflate priority=1";
const DEFLATE_PRIORITY_TWO: &str = "algo=deflate priority=2";
const LZ4_PRIORITY_TWO: &str = "algo=lz4 priority=2";
const PRIMARY_DEFLATE_LEVEL: &str = "priority=0 level=1";
const PRIMARY_DEFLATE_LITERAL_LEVEL: &str = "priority=0 level=0";
const PRIMARY_DEFLATE_MAX_LEVEL: &str = "algo=deflate level=10";
const SECONDARY_DEFLATE_FAST_LEVEL: &str = "priority=1 level=1";
const SECONDARY_DEFLATE_MAX_LEVEL: &str = "algo=deflate priority=2 level=10";
const SECONDARY_DEFLATE_DEFAULT_LEVEL: &str = "priority=1 level=-1";
const SECONDARY_DEFLATE_RESET: &str = "priority=1";
const INVALID_DEFLATE_LEVEL: &str = "priority=0 level=11";
const DEFLATE_DICTIONARY_PARAMETER: &str = "priority=0 dict=/run/zram-dictionary";
const INVALID_DEFLATE_WINDOW: &str = "priority=0 deflate.winbits=15";
const SMALL_DEFLATE_WINDOW: &str = "priority=0 deflate.winbits=-8";
const FUTURE_BACKEND_PARAMETER: &str = "priority=0 future_backend=opaque";
const UNKNOWN_ALGORITHM: &str = "algo=not-a-compressor level=1";
const LZ4_LEVEL: &str = "priority=0 level=1";
const LZ4_DICTIONARY_PARAMETER: &str = "priority=0 dict=/run/zram-dictionary";
const LZ4_DICTIONARY: &[u8] = b"oxide zram lz4 dictionary corpus";
const FIRST_BLOCK: u64 = 0;
const BLOCKS_PER_PAGE: u32 = PAGE_BYTES as u32 / crate::ZRAM_BLOCK_SIZE;
const FIRST_DEFLATE_LEVEL: i32 = 1;
const MAXIMUM_DEFLATE_LEVEL: i32 = 10;
const DEFAULT_DEFLATE_LEVEL: i32 = -1;
const UNSET_DEFLATE_LEVEL: i32 = crate::deflate::PARAM_NOT_SET;

fn lzo_page() -> alloc::vec::Vec<u8> {
    let mut page = alloc::vec![0; PAGE_BYTES];
    for chunk in page.chunks_mut(LZ4_DICTIONARY.len()) {
        chunk.copy_from_slice(&LZ4_DICTIONARY[..chunk.len()]);
    }
    page
}

#[test]
fn comp_algorithm_renders_only_compiled_backends_with_primary_selected() {
    let zram = Zram::new();
    assert_eq!(zram.algorithms(), "lzo [lz4] deflate ");
    zram.set_algorithm_text(DEFLATE_ALGORITHM).unwrap();
    assert_eq!(zram.algorithms(), "lzo lz4 [deflate] ");
}

#[test]
fn recomp_algorithm_omits_unconfigured_priorities() {
    let zram = Zram::new();
    assert_eq!(zram.recompression_algorithms(), "");
    zram.set_recomp_algorithm_text(LZ4_PRIORITY_TWO).unwrap();
    assert_eq!(zram.recompression_algorithms(), "#2: lzo [lz4] deflate \n");
    zram.set_recomp_algorithm_text(DEFLATE_PRIORITY_ONE).unwrap();
    assert_eq!(zram.recompression_algorithms(), "#1: lzo lz4 [deflate] \n#2: lzo [lz4] deflate \n");
}

#[test]
fn recomp_algorithm_allows_linux_same_backend_secondary_selection() {
    let zram = Zram::new();
    zram.set_recomp_algorithm_text("algo=lz4 priority=1").unwrap();
    assert_eq!(zram.recompression_algorithms(), "#1: lzo [lz4] deflate \n");
}

#[test]
fn lzo_packed_io_roundtrips_through_its_reusable_stream() {
    let zram = Zram::new();
    zram.set_algorithm_text(LZO_ALGORITHM).unwrap();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let page = lzo_page();
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_BLOCK, BLOCKS_PER_PAGE, page.clone())).unwrap();
    assert!(matches!(zram.state.lock().slots.get(0), Some(Slot::Packed { algorithm: Compression::Lzo, .. })));
    let mut read = BlockRequest::new_read(FIRST_BLOCK, BLOCKS_PER_PAGE, crate::ZRAM_BLOCK_SIZE);
    zram.submit_sync(&mut read).unwrap();
    assert_eq!(read.buffer, page);
}

#[test]
fn lzo_streams_release_on_reset_and_reinitialize_cleanly() {
    let zram = Zram::new();
    zram.set_algorithm_text(LZO_ALGORITHM).unwrap();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_BLOCK, BLOCKS_PER_PAGE, lzo_page())).unwrap();
    zram.reset().unwrap();
    zram.set_algorithm_text(LZO_ALGORITHM).unwrap();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let page = lzo_page();
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_BLOCK, BLOCKS_PER_PAGE, page.clone())).unwrap();
    let mut read = BlockRequest::new_read(FIRST_BLOCK, BLOCKS_PER_PAGE, crate::ZRAM_BLOCK_SIZE);
    zram.submit_sync(&mut read).unwrap();
    assert_eq!(read.buffer, page);
}

#[test]
fn lzo_secondary_recompression_replaces_literal_deflate_data() {
    let zram = Zram::new();
    zram.set_algorithm_text(DEFLATE_ALGORITHM).unwrap();
    zram.set_algorithm_params_text(PRIMARY_DEFLATE_LITERAL_LEVEL).unwrap();
    zram.set_recomp_algorithm_text("algo=lzo priority=1").unwrap();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let page = lzo_page();
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_BLOCK, BLOCKS_PER_PAGE, page.clone())).unwrap();
    zram.recompress_text("algo=lzo").unwrap();
    assert!(matches!(zram.state.lock().slots.get(0), Some(Slot::Packed { algorithm: Compression::Lzo, priority: 1, .. })));
    let mut read = BlockRequest::new_read(FIRST_BLOCK, BLOCKS_PER_PAGE, crate::ZRAM_BLOCK_SIZE);
    zram.submit_sync(&mut read).unwrap();
    assert_eq!(read.buffer, page);
}

#[test]
fn algorithm_params_targets_one_configured_compressor_at_a_time() {
    let zram = Zram::new();
    zram.set_algorithm_text(DEFLATE_ALGORITHM).unwrap();
    zram.set_recomp_algorithm_text(DEFLATE_PRIORITY_ONE).unwrap();
    zram.set_recomp_algorithm_text(DEFLATE_PRIORITY_TWO).unwrap();
    zram.set_algorithm_params_text(PRIMARY_DEFLATE_LEVEL).unwrap();
    zram.set_algorithm_params_text(SECONDARY_DEFLATE_FAST_LEVEL).unwrap();
    zram.set_algorithm_params_text(SECONDARY_DEFLATE_MAX_LEVEL).unwrap();
    let state = zram.state.lock();
    assert_eq!(state.primary_algorithm.level, FIRST_DEFLATE_LEVEL);
    assert_eq!(state.recompression_algorithms[0].as_ref().unwrap().level, FIRST_DEFLATE_LEVEL);
    assert_eq!(state.recompression_algorithms[1].as_ref().unwrap().level, MAXIMUM_DEFLATE_LEVEL);
}

#[test]
fn algorithm_params_name_lookup_uses_lowest_configured_priority() {
    let zram = Zram::new();
    zram.set_algorithm_text(DEFLATE_ALGORITHM).unwrap();
    zram.set_recomp_algorithm_text(DEFLATE_PRIORITY_ONE).unwrap();
    zram.set_algorithm_params_text(PRIMARY_DEFLATE_MAX_LEVEL).unwrap();
    let state = zram.state.lock();
    assert_eq!(state.primary_algorithm.level, MAXIMUM_DEFLATE_LEVEL);
    assert_eq!(state.recompression_algorithms[0].as_ref().unwrap().level, UNSET_DEFLATE_LEVEL);
}

#[test]
fn changing_algorithm_preserves_priority_owned_parameters() {
    let zram = Zram::new();
    zram.set_algorithm_text(DEFLATE_ALGORITHM).unwrap();
    zram.set_algorithm_params_text(PRIMARY_DEFLATE_MAX_LEVEL).unwrap();
    zram.set_algorithm_text("lz4").unwrap();
    zram.set_algorithm_text(DEFLATE_ALGORITHM).unwrap();
    assert_eq!(zram.state.lock().primary_algorithm.level, MAXIMUM_DEFLATE_LEVEL);
    zram.set_recomp_algorithm_text(DEFLATE_PRIORITY_ONE).unwrap();
    zram.set_algorithm_params_text(SECONDARY_DEFLATE_FAST_LEVEL).unwrap();
    zram.set_recomp_algorithm_text("algo=lz4 priority=1").unwrap();
    zram.set_recomp_algorithm_text(DEFLATE_PRIORITY_ONE).unwrap();
    assert_eq!(zram.state.lock().recompression_algorithms[0].as_ref().unwrap().level, FIRST_DEFLATE_LEVEL);
}

#[test]
fn algorithm_params_default_level_replaces_selected_deflate_parameters() {
    let zram = Zram::new();
    zram.set_recomp_algorithm_text(DEFLATE_PRIORITY_ONE).unwrap();
    zram.set_algorithm_params_text(SECONDARY_DEFLATE_FAST_LEVEL).unwrap();
    zram.set_algorithm_params_text(SECONDARY_DEFLATE_DEFAULT_LEVEL).unwrap();
    assert_eq!(zram.state.lock().recompression_algorithms[0].as_ref().unwrap().level, DEFAULT_DEFLATE_LEVEL);
    zram.set_algorithm_params_text(SECONDARY_DEFLATE_FAST_LEVEL).unwrap();
    zram.set_algorithm_params_text(SECONDARY_DEFLATE_RESET).unwrap();
    assert_eq!(zram.state.lock().recompression_algorithms[0].as_ref().unwrap().level, UNSET_DEFLATE_LEVEL);
}

#[test]
fn algorithm_params_defers_invalid_deflate_window_until_initialization_like_linux() {
    let zram = Zram::new();
    zram.set_algorithm_text(DEFLATE_ALGORITHM).unwrap();
    assert!(zram.set_algorithm_params_text(INVALID_DEFLATE_LEVEL).is_ok());
    assert_eq!(zram.set_disksize(PAGE_BYTES as u64), Err(block::BlockError::Einval));
    assert!(zram.set_algorithm_params_text(INVALID_DEFLATE_WINDOW).is_ok());
    assert_eq!(zram.set_disksize(PAGE_BYTES as u64), Err(block::BlockError::Einval));
    zram.set_algorithm_text("lz4").unwrap();
    zram.set_algorithm_params_text(LZ4_LEVEL).unwrap();
    assert_eq!(zram.state.lock().primary_algorithm.level, FIRST_DEFLATE_LEVEL);
}

#[test]
fn deflate_small_linux_window_packed_io_roundtrips() {
    let zram = Zram::new();
    zram.set_algorithm_text(DEFLATE_ALGORITHM).unwrap();
    zram.set_algorithm_params_text(SMALL_DEFLATE_WINDOW).unwrap();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let mut page = alloc::vec![0; PAGE_BYTES];
    for chunk in page.chunks_mut(LZ4_DICTIONARY.len()) {
        chunk.copy_from_slice(&LZ4_DICTIONARY[..chunk.len()]);
    }
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_BLOCK, BLOCKS_PER_PAGE, page.clone())).unwrap();
    assert!(matches!(zram.state.lock().slots.get(0), Some(Slot::Packed { algorithm: Compression::Deflate, .. })));
    let mut read = BlockRequest::new_read(FIRST_BLOCK, BLOCKS_PER_PAGE, crate::ZRAM_BLOCK_SIZE);
    zram.submit_sync(&mut read).unwrap();
    assert_eq!(read.buffer, page);
}

#[test]
fn deflate_retains_linux_generic_dictionary_parameters_for_a_later_lz4_selection() {
    let zram = Zram::new();
    zram.set_algorithm_text(DEFLATE_ALGORITHM).unwrap();
    zram.set_algorithm_params_with_dictionary_text(DEFLATE_DICTIONARY_PARAMETER, LZ4_DICTIONARY.to_vec()).unwrap();
    assert_eq!(zram.state.lock().primary_algorithm.dictionary, LZ4_DICTIONARY);
    zram.set_algorithm_text("lz4").unwrap();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let mut page = alloc::vec![0; PAGE_BYTES];
    for chunk in page.chunks_mut(LZ4_DICTIONARY.len()) {
        chunk.copy_from_slice(&LZ4_DICTIONARY[..chunk.len()]);
    }
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_BLOCK, BLOCKS_PER_PAGE, page.clone())).unwrap();
    let mut read = BlockRequest::new_read(FIRST_BLOCK, BLOCKS_PER_PAGE, crate::ZRAM_BLOCK_SIZE);
    zram.submit_sync(&mut read).unwrap();
    assert_eq!(read.buffer, page);
}

#[test]
fn lz4_dictionary_is_owned_by_the_selected_compressor_configuration() {
    let zram = Zram::new();
    assert_eq!(zram.set_algorithm_params_text(LZ4_DICTIONARY_PARAMETER), Err(block::BlockError::Einval));
    zram.set_algorithm_params_with_dictionary_text(LZ4_DICTIONARY_PARAMETER, LZ4_DICTIONARY.to_vec()).unwrap();
    assert_eq!(zram.state.lock().primary_algorithm.dictionary, LZ4_DICTIONARY);
    zram.set_algorithm_params_text("priority=0").unwrap();
    assert!(zram.state.lock().primary_algorithm.dictionary.is_empty());
}

#[test]
fn dictionary_open_failure_reset_leaves_linux_default_compressor_parameters() {
    let zram = Zram::new();
    zram.set_algorithm_params_with_dictionary_text(LZ4_DICTIONARY_PARAMETER, LZ4_DICTIONARY.to_vec()).unwrap();
    zram.reset_algorithm_params_text(LZ4_DICTIONARY_PARAMETER).unwrap();
    assert!(zram.state.lock().primary_algorithm.dictionary.is_empty());
}

#[test]
fn lz4_dictionary_packed_io_roundtrips_through_the_selected_configuration() {
    let zram = Zram::new();
    zram.set_algorithm_params_with_dictionary_text(LZ4_DICTIONARY_PARAMETER, LZ4_DICTIONARY.to_vec()).unwrap();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let mut page = alloc::vec![0; PAGE_BYTES];
    for chunk in page.chunks_mut(LZ4_DICTIONARY.len()) {
        chunk.copy_from_slice(&LZ4_DICTIONARY[..chunk.len()]);
    }
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_BLOCK, BLOCKS_PER_PAGE, page.clone())).unwrap();
    assert!(matches!(zram.state.lock().slots.get(0), Some(Slot::Packed { algorithm: Compression::Lz4, .. })));
    let mut read = BlockRequest::new_read(FIRST_BLOCK, BLOCKS_PER_PAGE, crate::ZRAM_BLOCK_SIZE);
    zram.submit_sync(&mut read).unwrap();
    assert_eq!(read.buffer, page);
}

#[test]
fn generic_parameter_parsers_ignore_unknown_named_fields_like_linux() {
    let zram = Zram::new();
    zram.set_algorithm_text(DEFLATE_ALGORITHM).unwrap();
    zram.set_algorithm_params_text(FUTURE_BACKEND_PARAMETER).unwrap();
    zram.set_recomp_algorithm_text("ignored=value algo=lz4 priority=1").unwrap();
    assert_eq!(zram.recompression_algorithms(), "#1: lzo [lz4] deflate \n");
}

#[test]
fn algorithm_params_enforces_linux_initialization_lifecycle_before_lookup() {
    let zram = Zram::new();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    assert_eq!(zram.set_algorithm_params_text(INVALID_DEFLATE_LEVEL), Err(block::BlockError::Ebusy));
    assert_eq!(zram.set_algorithm_params_text(UNKNOWN_ALGORITHM), Err(block::BlockError::Ebusy));
    assert_eq!(zram.set_recomp_algorithm_text(DEFLATE_PRIORITY_TWO), Err(block::BlockError::Ebusy));
}

#[test]
fn algorithm_params_rejects_missing_or_mismatched_configured_target() {
    let zram = Zram::new();
    assert_eq!(zram.set_algorithm_params_text(PRIMARY_DEFLATE_MAX_LEVEL), Err(block::BlockError::Einval));
    zram.set_recomp_algorithm_text(DEFLATE_PRIORITY_ONE).unwrap();
    assert_eq!(zram.set_algorithm_params_text("algo=lz4 priority=1 level=1"), Err(block::BlockError::Einval));
    assert!(matches!(zram.state.lock().recompression_algorithms[0].as_ref().unwrap().algorithm, Compression::Deflate));
}
