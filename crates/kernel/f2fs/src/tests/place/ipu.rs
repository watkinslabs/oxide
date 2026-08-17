//! Every arm of both in-place ladders, and the order between them.
//!
//! One arm per test, each with the state that arms it and nothing else, so a
//! test that passes says which condition produced the answer. The refusals are
//! checked AGAINST an armed policy that would otherwise say yes — a refusal
//! tested against a mount that was going to refuse anyway proves nothing.

use crate::place::bits;
use crate::place::ipu::{self, Facts};
use crate::place::limits::DEF_MIN_IPU_UTIL;

/// A mount with everything armed and a file with nothing wrong with it: the
/// baseline every refusal below is measured against.
fn forced() -> Facts {
    Facts { have_io: true, policy: bits::bit(bits::FORCE), min_ipu_util: DEF_MIN_IPU_UTIL,
            ..Facts::default() }
}

/// Nothing armed is the whole answer: a mount that armed no policy writes out
/// of place whatever the file and whatever the pressure.
#[test]
fn an_unarmed_mount_never_writes_in_place() {
    let f = Facts { have_io: true, ..Facts::default() };
    assert!(!ipu::need_inplace_update(&f, || true));
    assert!(!ipu::need_inplace_update(&Facts { cold: false, ..f }, || true));
}

/// `FORCE` asks nothing else.
#[test]
fn the_force_policy_writes_in_place_always() {
    assert!(ipu::need_inplace_update(&forced(), || false));
}

/// The refusals come FIRST. Each of these is a state in which no policy may
/// put a write back in place, and each is checked against `FORCE`.
#[test]
fn the_refusals_beat_every_armed_policy() {
    let cases: [(&str, Facts); 7] = [
        ("lfs", Facts { lfs: true, ..forced() }),
        ("fsck", Facts { need_fsck: true, ..forced() }),
        ("dir", Facts { dir: true, ..forced() }),
        ("quota", Facts { quota: true, ..forced() }),
        ("atomic", Facts { atomic: true, ..forced() }),
        ("compressed", Facts { compressed: true, ..forced() }),
        ("gcing", Facts { gcing: true, ..forced() }),
    ];
    for (name, f) in cases {
        assert!(!ipu::need_inplace_update(&f, || true), "{name} should have refused");
    }
}

/// A file being aligned for a swap area is refused from BOTH sides: the
/// migration is moving its blocks, and a rewrite under it would move one back.
#[test]
fn an_aligned_write_is_refused_from_both_ladders() {
    let f = Facts { aligned_write: true, ..forced() };
    assert!(ipu::should_update_outplace(&f));
    assert!(!ipu::should_update_inplace(&f, || true));
    assert!(!ipu::need_inplace_update(&f, || true));
}

/// A pinned file's blocks may not move, so it is the one file the refusals let
/// through — and the reasons ladder then answers yes for it, whatever is armed.
#[test]
fn a_pinned_file_is_written_in_place_with_nothing_armed() {
    let f = Facts { pinned: true, have_io: true, ..Facts::default() };
    assert!(!ipu::should_update_outplace(&f));
    assert!(ipu::need_inplace_update(&f, || false));
}

/// A cold file's blocks are expected to stay put — unless it has asked for
/// out-of-place writes, which is the stronger statement of the two.
#[test]
fn a_cold_file_is_written_in_place_unless_it_asked_otherwise() {
    let f = Facts { cold: true, have_io: true, ..Facts::default() };
    assert!(ipu::need_inplace_update(&f, || false));
    // The request for out-of-place writes is a refusal in its own right, so
    // the answer is no even before the cold mark is consulted.
    assert!(!ipu::need_inplace_update(&Facts { opu_write: true, ..f }, || false));
}

/// `SSR` asks the allocator, and asks it only when armed.
#[test]
fn the_ssr_policy_follows_the_allocator() {
    let f = Facts { have_io: true, policy: bits::bit(bits::SSR), ..Facts::default() };
    assert!(ipu::need_inplace_update(&f, || true));
    assert!(!ipu::need_inplace_update(&f, || false));
    // Unarmed, the allocator is not even asked.
    let mut asked = false;
    let g = Facts { policy: bits::bit(bits::FSYNC), ..f };
    assert!(!ipu::need_inplace_update(&g, || { asked = true; true }));
    assert!(!asked, "the pressure was measured for a mount that did not arm it");
}

/// `UTIL` fires strictly above the threshold, not at it.
#[test]
fn the_utilisation_policy_fires_above_the_threshold() {
    let f = Facts { have_io: true, policy: bits::bit(bits::UTIL), min_ipu_util: 70,
                    ..Facts::default() };
    assert!(!ipu::need_inplace_update(&Facts { util: 69, ..f }, || false));
    assert!(!ipu::need_inplace_update(&Facts { util: 70, ..f }, || false));
    assert!(ipu::need_inplace_update(&Facts { util: 71, ..f }, || false));
}

/// `SSR_UTIL` needs BOTH, which is what makes it a policy of its own rather
/// than the two above armed together.
#[test]
fn the_combined_policy_needs_both_conditions() {
    let f = Facts { have_io: true, policy: bits::bit(bits::SSR_UTIL), min_ipu_util: 70,
                    util: 90, ..Facts::default() };
    assert!(ipu::need_inplace_update(&f, || true));
    assert!(!ipu::need_inplace_update(&f, || false));
    assert!(!ipu::need_inplace_update(&Facts { util: 50, ..f }, || true));
}

/// `FSYNC` is the default, and it fires only for the writes an `fsync` armed.
#[test]
fn the_fsync_policy_fires_only_for_the_call_that_armed_it() {
    let f = Facts { have_io: true, policy: bits::bit(bits::FSYNC), ..Facts::default() };
    assert!(!ipu::need_inplace_update(&f, || true));
    assert!(ipu::need_inplace_update(&Facts { need_ipu: true, ..f }, || true));
}

/// `ASYNC` takes the writes nothing is waiting on, and never an enciphered
/// file's.
#[test]
fn the_async_policy_takes_unwaited_plaintext_writes() {
    let f = Facts { have_io: true, policy: bits::bit(bits::ASYNC), async_write: true,
                    ..Facts::default() };
    assert!(ipu::need_inplace_update(&f, || false));
    assert!(!ipu::need_inplace_update(&Facts { async_write: false, ..f }, || false));
    assert!(!ipu::need_inplace_update(&Facts { encrypted: true, ..f }, || false));
    // No write in flight is no answer about its urgency.
    assert!(!ipu::need_inplace_update(&Facts { have_io: false, ..f }, || false));
}

/// `HONOR_OPU_WRITE` lets a file that asked for out-of-place writes have them,
/// ahead of every other armed policy — including `FORCE`.
#[test]
fn honouring_an_out_of_place_request_beats_the_force_policy() {
    let f = Facts { opu_write: true, have_io: true,
                    policy: bits::bit(bits::FORCE) | bits::bit(bits::HONOR_OPU_WRITE),
                    ..Facts::default() };
    assert!(!ipu::check_policy(&f, || true));
    // Without the honouring bit the request is a refusal in its own right, so
    // the answer is still no — but for the other reason.
    let g = Facts { policy: bits::bit(bits::FORCE), ..f };
    assert!(ipu::check_policy(&g, || true));
    assert!(ipu::should_update_outplace(&g));
}

/// With checkpointing off the two states part company: a block the last
/// checkpoint names may not be touched, and one it does not name may be
/// rewritten even by a mount that armed nothing.
#[test]
fn checkpointing_off_splits_on_whether_the_block_is_in_the_checkpoint() {
    let f = Facts { have_io: true, cp_disabled: true, ..Facts::default() };
    assert!(ipu::need_inplace_update(&Facts { checkpointed: false, ..f }, || false));
    assert!(!ipu::need_inplace_update(&Facts { checkpointed: true, ..f }, || false));
    // And neither fires without a write in flight to ask about.
    assert!(!ipu::need_inplace_update(&Facts { have_io: false, ..f }, || false));
}

/// A volume that never overwrites in place arms nothing; a small one arms the
/// lot and keeps honouring out-of-place requests; everything else arms the
/// `fsync` policy alone.
#[test]
fn the_armed_set_follows_the_volume_size() {
    use crate::place::limits::SMALL_VOLUME_SEGMENTS;
    assert_eq!(ipu::mount_policy(true, 16), bits::DISABLE);
    assert_eq!(ipu::mount_policy(true, SMALL_VOLUME_SEGMENTS * 4), bits::DISABLE);
    assert_eq!(ipu::mount_policy(false, SMALL_VOLUME_SEGMENTS),
               bits::bit(bits::FORCE) | bits::bit(bits::HONOR_OPU_WRITE));
    assert_eq!(ipu::mount_policy(false, SMALL_VOLUME_SEGMENTS + 1), bits::bit(bits::FSYNC));
}

/// A data-only sync always asks for in-place writes; a full sync asks for them
/// up to and including the threshold, and not past it.
#[test]
fn a_sync_asks_for_in_place_writes_for_a_short_tail() {
    assert!(ipu::fsync_wants_ipu(true, 4096, 8));
    assert!(ipu::fsync_wants_ipu(false, 8, 8));
    assert!(!ipu::fsync_wants_ipu(false, 9, 8));
}
