//! The signed inode-number delta, and that resuming a listing at a caller
//! position produces exactly the same walk a full listing would.

use alloc::vec::Vec;

use super::{apply_delta, SYNTHETIC_ENTRIES};
use crate::test_image::Builder;
use crate::volume::Volume;

#[test]
fn zero_delta_is_the_base_unchanged() {
    assert_eq!(apply_delta(1000, 0), 1000);
}

#[test]
fn positive_delta_adds() {
    assert_eq!(apply_delta(1000, 5), 1005);
}

/// A name whose inode was allocated BEFORE its header's base carries a
/// NEGATIVE delta. Reading the same bit pattern as unsigned would add nearly
/// 65536 instead of subtracting — `lib.rs` names this as the failure that
/// still looks like a plausible inode number.
#[test]
fn negative_delta_subtracts_rather_than_wrapping_to_a_huge_positive_number() {
    let delta = (-5i16) as u16;
    assert_eq!(apply_delta(1000, delta), 995);
    // The unsigned reading a careless implementation would produce instead.
    let wrong_unsigned = 1000u32.wrapping_add(u32::from(delta));
    assert_ne!(apply_delta(1000, delta), wrong_unsigned);
    assert!(wrong_unsigned > 65000); // "still looks like an inode number"
}

#[test]
fn delta_at_the_signed_extremes_round_trips() {
    assert_eq!(apply_delta(40000, i16::MIN as u16), 40000 - 32768);
    assert_eq!(apply_delta(40000, i16::MAX as u16), 40000 + 32767);
}

/// Build a root with enough entries to carry a real name index, then prove
/// `read_dir_from` resumes correctly: a walk from 0 matches a plain
/// `read_dir`, a walk from `SYNTHETIC_ENTRIES` (exactly what `mount/ops.rs`
/// passes right after emitting `.` and `..`) matches it too, and resuming at
/// any entry's `next_pos` yields precisely the entries after it.
///
/// This is a regression pin for `index_by_pos`: an earlier version returned
/// `Ok((start, pos))` for `pos <= SYNTHETIC_ENTRIES` instead of
/// `Ok((start, 0))`, so the on-disk length the walk resumed at started 1-3
/// bytes too high, and `next_pos` on every entry read after that carried the
/// same offset forward.
#[test]
fn read_dir_from_resumes_exactly_where_read_dir_would_be() {
    let names = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"];
    let mut b = Builder::new();
    for n in names { b = b.file(n, n.as_bytes()); }
    let vol = Volume::mount_with(b.build(), Default::default()).unwrap();
    let root = vol.read_inode(vol.root_reference()).unwrap();

    let full = vol.read_dir(&root).unwrap();
    assert_eq!(full.len(), names.len());

    // (a) pos == 0 is definitionally read_dir, but pin it anyway: it is the
    // baseline every other assertion here is compared against.
    let from_zero = vol.read_dir_from(&root, 0).unwrap();
    assert_eq!(from_zero, full);

    // The regression: this is the exact call `mount/ops.rs::iterate` makes
    // for an ordinary first real-entry fetch, right after `.` and `..`.
    let from_synthetic = vol.read_dir_from(&root, SYNTHETIC_ENTRIES).unwrap();
    assert_eq!(from_synthetic, full);

    // (b) resuming at each entry's own `next_pos` yields exactly the
    // entries strictly after it — proves the index is actually being used
    // to seed the walk, not merely that pos 0 and pos 3 happen to agree.
    // `read_dir_from` is only obliged to seed AT OR BEFORE `pos` (like a
    // page cache, not an exact cursor); the caller drops anything at or
    // before `pos` the same way `mount/ops.rs::iterate` does.
    for (i, entry) in full.iter().enumerate() {
        let pos = entry.next_pos;
        let resumed: Vec<_> = vol.read_dir_from(&root, pos).unwrap()
            .into_iter().filter(|e| e.next_pos > pos).collect();
        let want: Vec<_> = full[i + 1..].to_vec();
        assert_eq!(resumed, want, "resume after entry {i} ({})", entry.name);
    }
}
