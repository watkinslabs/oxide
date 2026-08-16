//! The move ladder: every refusal, and the order between them.

use super::*;
use syscall::errno::Errno;

const BLK: u64 = crate::uapi::BLKSIZE as u64;

fn reg(size: u64) -> Facts { Facts { is_reg: true, size, ..Facts::default() } }

fn go(src: &Facts, dst: &Facts, pos_in: u64, pos_out: u64, len: u64)
    -> Result<Option<Plan>, Errno> {
    plan(false, true, src, dst, pos_in, pos_out, len)
}

// ------------------------------------------------------------------ refusals

#[test]
fn a_read_only_mount_refuses_before_anything_else() {
    // Even a request that is wrong in three other ways is told the mount
    // first: the mount is what makes every one of them unanswerable.
    let bad = Facts::default();
    assert_eq!(plan(false, false, &bad, &bad, 1, 1, 1), Err(Errno::Erofs));
}

#[test]
fn both_ends_must_be_regular_files() {
    let d = Facts::default();
    assert_eq!(go(&d, &reg(BLK), 0, 0, BLK), Err(Errno::Einval));
    assert_eq!(go(&reg(BLK), &d, 0, 0, BLK), Err(Errno::Einval));
}

#[test]
fn an_encrypted_end_can_never_do_this() {
    let e = Facts { encrypted: true, ..reg(BLK) };
    assert_eq!(go(&e, &reg(BLK), 0, 0, BLK), Err(Errno::Eopnotsupp));
    assert_eq!(go(&reg(BLK), &e, 0, 0, BLK), Err(Errno::Eopnotsupp));
}

#[test]
fn the_type_refusal_comes_before_the_encryption_one() {
    let e = Facts { is_reg: false, encrypted: true, size: BLK, ..Facts::default() };
    assert_eq!(go(&e, &reg(BLK), 0, 0, BLK), Err(Errno::Einval));
}

#[test]
fn a_position_that_would_be_negative_is_refused() {
    let s = reg(BLK);
    let neg = 1u64 << 63;
    assert_eq!(go(&s, &s, neg, 0, BLK), Err(Errno::Einval));
    assert_eq!(go(&s, &s, 0, neg, BLK), Err(Errno::Einval));
}

#[test]
fn a_compressed_or_pinned_end_can_never_do_this() {
    let big = reg(4 * BLK);
    for f in [Facts { compressed: true, ..big }, Facts { pinned: true, ..big }] {
        assert_eq!(go(&f, &big, 0, 0, BLK), Err(Errno::Eopnotsupp));
        assert_eq!(go(&big, &f, 0, 0, BLK), Err(Errno::Eopnotsupp));
    }
}

#[test]
fn an_atomic_end_is_refused_with_a_different_errno_than_a_compressed_one() {
    let big = reg(4 * BLK);
    let a = Facts { atomic: true, ..big };
    assert_eq!(go(&a, &big, 0, 0, BLK), Err(Errno::Einval));
    assert_eq!(go(&big, &a, 0, 0, BLK), Err(Errno::Einval));
    // And the never-possible refusal is reported ahead of the not-now one.
    let both = Facts { atomic: true, compressed: true, ..big };
    assert_eq!(go(&both, &big, 0, 0, BLK), Err(Errno::Eopnotsupp));
}

#[test]
fn a_range_past_the_end_of_the_source_is_refused() {
    let s = reg(2 * BLK);
    assert_eq!(go(&s, &s, BLK, 0, 2 * BLK), Err(Errno::Einval));
}

#[test]
fn a_start_past_the_end_is_refused_even_asking_for_the_rest() {
    let s = reg(2 * BLK);
    assert_eq!(go(&s, &s, 3 * BLK, 0, 0), Err(Errno::Einval));
}

#[test]
fn a_length_that_overflows_is_refused_rather_than_wrapping() {
    let s = reg(2 * BLK);
    assert_eq!(go(&s, &s, BLK, 0, u64::MAX), Err(Errno::Einval));
}

// ----------------------------------------------------------------- alignment

#[test]
fn every_end_must_sit_on_a_block_boundary() {
    let s = reg(8 * BLK);
    assert_eq!(go(&s, &s, 1, 0, BLK), Err(Errno::Einval));
    assert_eq!(go(&s, &s, 0, 1, BLK), Err(Errno::Einval));
    assert_eq!(go(&s, &s, 0, 0, BLK + 1), Err(Errno::Einval));
}

#[test]
fn a_range_reaching_the_end_takes_the_last_partial_block_whole() {
    // Three and a half blocks of file; a move from block one to the end is
    // two and a half blocks, rounded out to three.
    let s = reg(3 * BLK + 512);
    let p = go(&s, &reg(0), BLK, 0, 2 * BLK + 512).unwrap().unwrap();
    assert_eq!(p.blocks, 3);
    assert_eq!(p.src_index, 1);
    // The destination grows only to what was asked for, not to the padding.
    assert_eq!(p.dst_size, 2 * BLK + 512);
}

#[test]
fn a_length_of_zero_means_the_rest_of_the_file() {
    let s = reg(3 * BLK + 512);
    let p = go(&s, &reg(0), BLK, 0, 0).unwrap().unwrap();
    assert_eq!(p.blocks, 3);
    assert_eq!(p.dst_size, 2 * BLK + 512);
}

#[test]
fn a_length_of_zero_on_an_empty_file_moves_nothing() {
    // The rest of an empty file is nothing, which is a success with no work.
    assert_eq!(go(&reg(0), &reg(0), 0, 0, 0), Ok(None));
}

// ------------------------------------------------------------------ same file

#[test]
fn moving_a_range_onto_itself_does_nothing_and_succeeds() {
    let s = reg(8 * BLK);
    assert_eq!(plan(true, true, &s, &s, BLK, BLK, BLK), Ok(None));
}

#[test]
fn moving_a_range_forward_onto_its_own_tail_is_refused() {
    let s = reg(8 * BLK);
    assert_eq!(plan(true, true, &s, &s, 0, BLK, 4 * BLK), Err(Errno::Einval));
}

#[test]
fn moving_a_range_backwards_within_one_file_is_allowed() {
    let s = reg(8 * BLK);
    let p = plan(true, true, &s, &s, 4 * BLK, 0, 2 * BLK).unwrap().unwrap();
    assert_eq!((p.src_index, p.dst_index, p.blocks), (4, 0, 2));
}

#[test]
fn moving_a_range_past_its_own_end_is_allowed() {
    let s = reg(8 * BLK);
    let p = plan(true, true, &s, &s, 0, 4 * BLK, 2 * BLK).unwrap().unwrap();
    assert_eq!((p.src_index, p.dst_index, p.blocks), (0, 4, 2));
}

// -------------------------------------------------------------- the new length

#[test]
fn a_destination_that_already_reaches_further_keeps_its_length() {
    let s = reg(8 * BLK);
    let d = reg(16 * BLK);
    let p = go(&s, &d, 0, 0, 2 * BLK).unwrap().unwrap();
    assert_eq!(p.dst_size, 16 * BLK);
}

#[test]
fn a_destination_written_past_its_end_grows_to_exactly_there() {
    let s = reg(8 * BLK);
    let d = reg(BLK);
    let p = go(&s, &d, 0, 4 * BLK, 2 * BLK).unwrap().unwrap();
    assert_eq!(p.dst_size, 6 * BLK);
}
