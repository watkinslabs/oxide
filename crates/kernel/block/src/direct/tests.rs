use super::*;

const BS: u32 = 512;
/// Eight blocks — 4096 bytes.
const CAP: u64 = 8;

// The alignment rule direct I/O cannot hide: there is no cached page to take a
// partial block apart with, so a request that is not whole blocks is refused
// rather than rounded.
#[test]
fn a_misaligned_offset_is_refused() {
    assert_eq!(plan(false, 1, 512, BS, CAP), Err(VfsError::Einval));
    assert_eq!(plan(false, 511, 512, BS, CAP), Err(VfsError::Einval));
    assert_eq!(plan(true, 513, 512, BS, CAP), Err(VfsError::Einval));
}

#[test]
fn a_misaligned_length_is_refused() {
    assert_eq!(plan(false, 0, 1, BS, CAP), Err(VfsError::Einval));
    assert_eq!(plan(false, 0, 513, BS, CAP), Err(VfsError::Einval));
    assert_eq!(plan(true, 512, 1023, BS, CAP), Err(VfsError::Einval));
}

// A zero-length transfer is not an error and never reaches the device.
#[test]
fn a_zero_length_transfer_is_done_with_no_bytes() {
    assert_eq!(plan(false, 0, 0, BS, CAP), Ok(Plan::Done(0)));
    assert_eq!(plan(true, 1024, 0, BS, CAP), Ok(Plan::Done(0)));
}

#[test]
fn an_aligned_in_range_transfer_becomes_a_block_range() {
    assert_eq!(plan(false, 1024, 1024, BS, CAP),
               Ok(Plan::Io { start_block: 2, len_blocks: 2, bytes: 1024 }));
    assert_eq!(plan(true, 0, 4096, BS, CAP),
               Ok(Plan::Io { start_block: 0, len_blocks: 8, bytes: 4096 }));
}

// The two directions differ past the end and must not be folded together: a
// read there has nothing to return, a write there has nowhere to put its
// bytes.
#[test]
fn starting_past_the_end_is_eof_for_a_read_and_enospc_for_a_write() {
    assert_eq!(plan(false, 4096, 512, BS, CAP), Ok(Plan::Done(0)));
    assert_eq!(plan(false, 8192, 512, BS, CAP), Ok(Plan::Done(0)));
    assert_eq!(plan(true, 4096, 512, BS, CAP), Err(VfsError::Enospc));
}

// Running OFF the end is shortened, not refused — in both directions.
#[test]
fn a_transfer_that_runs_off_the_end_is_shortened() {
    assert_eq!(plan(false, 3584, 4096, BS, CAP),
               Ok(Plan::Io { start_block: 7, len_blocks: 1, bytes: 512 }));
    assert_eq!(plan(true, 3072, 4096, BS, CAP),
               Ok(Plan::Io { start_block: 6, len_blocks: 2, bytes: 1024 }));
}

// A shortened length stays block-aligned, which is what lets the device see a
// whole block range after the clamp.
#[test]
fn the_shortened_length_is_still_whole_blocks() {
    for off in (0..4096u64).step_by(512) {
        let Ok(Plan::Io { bytes, len_blocks, .. }) = plan(false, off, 1 << 20, BS, CAP)
            else { panic!("in-range offset must plan a transfer") };
        assert_eq!(bytes % BS as usize, 0);
        assert_eq!(bytes, len_blocks as usize * BS as usize);
    }
}

// A device with no stated block size cannot have an alignment rule at all;
// refusing beats dividing by zero.
#[test]
fn a_zero_block_size_is_refused() {
    assert_eq!(plan(false, 0, 0, 0, CAP), Err(VfsError::Einval));
}

// A zero-capacity device is past the end at every offset.
#[test]
fn an_empty_device_is_eof_at_offset_zero() {
    assert_eq!(plan(false, 0, 512, BS, 0), Ok(Plan::Done(0)));
    assert_eq!(plan(true, 0, 512, BS, 0), Err(VfsError::Enospc));
}
