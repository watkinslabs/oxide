//! The refusal ladder, one rung at a time.

use super::*;
use crate::fallocate::uapi::*;

/// Every mode that names an operation, plus the bare one.
const MODES: [u32; 6] = [0, FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE,
                         FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_ZERO_RANGE,
                         FALLOC_FL_INSERT_RANGE];

#[test]
fn an_ordinary_file_passes_every_mode() {
    for m in MODES { assert_eq!(check(&Gate::ordinary(), m), Ok(()), "mode {m:#x}"); }
}

#[test]
fn a_failed_checkpoint_refuses_everything_with_an_io_error() {
    let g = Gate { cp_error: true, ..Gate::ordinary() };
    for m in MODES { assert_eq!(check(&g, m), Err(Errno::Eio), "mode {m:#x}"); }
}

#[test]
fn a_volume_that_cannot_checkpoint_and_has_no_room_reports_no_space() {
    let g = Gate { checkpoint_ready: false, ..Gate::ordinary() };
    assert_eq!(check(&g, 0), Err(Errno::Enospc));
}

#[test]
fn a_missing_codec_and_an_aliased_device_are_both_unsupported() {
    assert_eq!(check(&Gate { compress_backend_ready: false, ..Gate::ordinary() }, 0),
               Err(Errno::Eopnotsupp));
    assert_eq!(check(&Gate { device_aliasing: true, ..Gate::ordinary() }, 0),
               Err(Errno::Eopnotsupp));
}

#[test]
fn anything_but_a_regular_file_is_invalid() {
    let g = Gate { regular: false, ..Gate::ordinary() };
    for m in MODES { assert_eq!(check(&g, m), Err(Errno::Einval), "mode {m:#x}"); }
}

#[test]
fn an_encrypted_file_refuses_the_two_that_move_blocks() {
    let g = Gate { encrypted: true, ..Gate::ordinary() };
    assert_eq!(check(&g, FALLOC_FL_COLLAPSE_RANGE), Err(Errno::Eopnotsupp));
    assert_eq!(check(&g, FALLOC_FL_INSERT_RANGE), Err(Errno::Eopnotsupp));
    // The three that leave every block at the index it was at are fine: the
    // contents are keyed to that index and nothing moved.
    assert!(check(&g, FALLOC_FL_PUNCH_HOLE).is_ok());
    assert!(check(&g, FALLOC_FL_ZERO_RANGE).is_ok());
    assert!(check(&g, FALLOC_FL_KEEP_SIZE).is_ok());
}

#[test]
fn a_bit_nobody_honours_is_refused_rather_than_masked() {
    assert_eq!(check(&Gate::ordinary(), 1 << 31), Err(Errno::Eopnotsupp));
    assert_eq!(check(&Gate::ordinary(), FALLOC_FL_KEEP_SIZE | 0x04), Err(Errno::Eopnotsupp));
    assert_eq!(check(&Gate::ordinary(), FALLOC_FL_SUPPORTED), Ok(()));
}

#[test]
fn a_pinned_or_compressed_file_refuses_every_partial_operation() {
    for g in [Gate { pinned: true, ..Gate::ordinary() },
              Gate { compressed: true, ..Gate::ordinary() }] {
        for m in [FALLOC_FL_PUNCH_HOLE, FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_ZERO_RANGE,
                  FALLOC_FL_INSERT_RANGE] {
            assert_eq!(check(&g, m), Err(Errno::Eopnotsupp), "{g:?} mode {m:#x}");
        }
        // The plain allocation is what a pinned file is FOR, so it passes.
        assert!(check(&g, 0).is_ok());
        assert!(check(&g, FALLOC_FL_KEEP_SIZE).is_ok());
    }
}

#[test]
fn the_first_rung_is_the_one_reported() {
    // Every rung tripped at once: the answer is the earliest, and dropping it
    // uncovers the next.
    let g = Gate { cp_error: true, checkpoint_ready: false, compress_backend_ready: false,
                   device_aliasing: true, regular: false, encrypted: true, compressed: true,
                   pinned: true };
    assert_eq!(check(&g, FALLOC_FL_COLLAPSE_RANGE), Err(Errno::Eio));
    let g = Gate { cp_error: false, ..g };
    assert_eq!(check(&g, FALLOC_FL_COLLAPSE_RANGE), Err(Errno::Enospc));
    let g = Gate { checkpoint_ready: true, ..g };
    assert_eq!(check(&g, FALLOC_FL_COLLAPSE_RANGE), Err(Errno::Eopnotsupp));
    let g = Gate { compress_backend_ready: true, device_aliasing: false, ..g };
    assert_eq!(check(&g, FALLOC_FL_COLLAPSE_RANGE), Err(Errno::Einval));
    let g = Gate { regular: true, ..g };
    assert_eq!(check(&g, FALLOC_FL_COLLAPSE_RANGE), Err(Errno::Eopnotsupp));
    let g = Gate { encrypted: false, compressed: false, pinned: false, ..g };
    assert_eq!(check(&g, FALLOC_FL_COLLAPSE_RANGE), Ok(()));
}
