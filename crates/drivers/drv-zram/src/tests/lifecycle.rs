//! zram initialized-action and writeback-batch ABI contracts.

use block::BlockError;

use crate::state::PAGE_BYTES;
use crate::Zram;

/// Linux sysfs rejects an uninitialized lifecycle action with `EINVAL`.
const UNINITIALIZED_ERROR: BlockError = BlockError::Einval;
/// Valid one-page initialization used to prove the guard permits actions.
const INITIALIZED_DEVICE_BYTES: u64 = PAGE_BYTES as u64;
/// Linux rejects zero rather than silently normalizing the batch count.
const ZERO_WRITEBACK_BATCH_TEXT: &str = "0";
/// A valid writeback batch count remains visible as configured state.
const VALID_WRITEBACK_BATCH_TEXT: &str = "2";
const VALID_WRITEBACK_BATCH_COUNT: u32 = 2;

#[test]
fn uninitialized_lifecycle_actions_fail_with_einval() {
    let zram = Zram::new();
    assert_eq!(zram.compact(), Err(UNINITIALIZED_ERROR));
    assert_eq!(zram.mark_idle_text("all"), Err(UNINITIALIZED_ERROR));
    assert_eq!(zram.writeback_all(), Err(UNINITIALIZED_ERROR));
    assert_eq!(zram.writeback_page_index(0), Err(UNINITIALIZED_ERROR));
    assert_eq!(zram.writeback_text("all"), Err(UNINITIALIZED_ERROR));
    assert_eq!(zram.recompress_text("priority=1"), Err(UNINITIALIZED_ERROR));
}

#[test]
fn initialized_lifecycle_actions_reach_their_native_validation() {
    let zram = Zram::new();
    zram.set_disksize(INITIALIZED_DEVICE_BYTES).unwrap();
    assert_eq!(zram.compact(), Ok(()));
    assert_eq!(zram.mark_idle_text("all"), Ok(()));
    assert_eq!(zram.writeback_all(), Ok(()));
    assert_eq!(zram.writeback_text("invalid"), Err(BlockError::Enxio));
    assert_eq!(zram.recompress_text("priority=1"), Err(BlockError::Einval));
}

#[test]
fn writeback_batch_size_rejects_zero_without_state_change() {
    let zram = Zram::new();
    let initial = zram.stats().writeback_batch_size;
    assert_eq!(zram.set_writeback_batch_size_text(ZERO_WRITEBACK_BATCH_TEXT), Err(UNINITIALIZED_ERROR));
    assert_eq!(zram.stats().writeback_batch_size, initial);
    zram.set_writeback_batch_size_text(VALID_WRITEBACK_BATCH_TEXT).unwrap();
    assert_eq!(zram.stats().writeback_batch_size, VALID_WRITEBACK_BATCH_COUNT);
}
