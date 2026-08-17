//! A checkpoint places the quota-file blocks it CHANGED, and not the rest.
//!
//! Every write on this filesystem is placed out of place, so writing a block
//! back costs a fresh block, a node update and a stale block for the cleaner.
//! A flush that wrote the whole quota file therefore re-placed all of it every
//! time one identity's usage moved — which is why the reference reaches a
//! single quota-file block through the quota inode's mapping and writes that
//! one.
//!
//! The observable is the block ADDRESS of each index of the quota file across
//! two checkpoints: an index that was rewritten has a new address, one that was
//! left alone has the address it had.

use super::*;
use super::fixture::{with_quota, QUOTA_INO, UID};

/// Identities charged before the measurement, enough that the tree grows past
/// one filesystem block of leaves. Each one is a file, and each file's inode
/// charge makes a record the tree has no slot for.
const CROWD: u32 = 200;

/// The block address of every index of the quota file, `None` for a hole.
fn placement(v: &Volume<MemImage>) -> Vec<Option<u32>> {
    let inode = v.read_inode(QUOTA_INO).unwrap();
    let last = (inode.size as usize).div_ceil(BLKSIZE);
    (0..last as u64)
        .map(|i| match v.map_block(&inode, QUOTA_INO, i).unwrap() {
            crate::volume::map::Mapped::At(a) => Some(a),
            _ => None,
        })
        .collect()
}

/// Indexes whose address moved between two placements. A file that grew counts
/// its new indexes as moved, which is what they are.
fn moved(before: &[Option<u32>], after: &[Option<u32>]) -> usize {
    (0..after.len()).filter(|&i| before.get(i) != Some(&after[i])).count()
}

/// A volume whose quota file has been grown to several filesystem blocks by
/// charging `CROWD` identities, and committed so every block has an address.
fn crowded() -> Volume<MemImage> {
    let mut v = with_quota(0, 0, false);
    for i in 0..CROWD {
        let name = alloc::format!("f{i}");
        v.create(ROOT_INO, name.as_bytes(), &fixture::spec_of(10_000 + i), None).unwrap();
    }
    v.commit().unwrap();
    v
}

#[test]
fn changing_one_identitys_usage_re_places_two_blocks_of_the_quota_file() {
    let mut v = crowded();
    let before = placement(&v);
    assert!(before.len() >= 6,
            "the fixture's quota file is too small for this to measure anything: {} blocks",
            before.len());

    // One more file for an identity the tree already holds a slot for: its
    // record is rewritten in place, so the only blocks with anything new in
    // them are the leaf it sits in and the header.
    v.create(ROOT_INO, b"one-more", &fixture::spec_of(10_000), None).unwrap();
    v.commit().unwrap();

    let after = placement(&v);
    let n = moved(&before, &after);
    assert!(n <= 3, "{n} of {} quota-file blocks were re-placed to change one record",
            after.len());
    assert!(n >= 1, "nothing was written at all, so the record did not reach the file");
}

#[test]
fn the_record_a_partial_write_leaves_behind_is_the_one_a_fresh_mount_reads() {
    // The counterpart to the test above: writing fewer blocks is only correct
    // if the file is still whole. The volume is committed and mounted again,
    // and every identity's record is read back through the tree.
    let mut v = crowded();
    v.create(ROOT_INO, b"one-more", &fixture::spec_of(10_000), None).unwrap();
    v.commit().unwrap();
    let want: Vec<u64> = (0..CROWD)
        .map(|i| v.quota_record(USRQUOTA, 10_000 + i).unwrap().curinodes)
        .collect();
    assert_eq!(want[0], 2, "the identity with two files was not charged twice");

    let bytes = v.into_source().snapshot();
    let mut o = Options::defaults();
    o.usrquota = false;
    let mut fresh = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), o, true)
        .unwrap();

    for i in 0..CROWD {
        assert_eq!(fresh.quota_record(USRQUOTA, 10_000 + i).unwrap().curinodes,
                   want[i as usize],
                   "identity {} lost its record across the mount", 10_000 + i);
    }
    // And the fixture's own record, which no test above touched.
    assert!(fresh.quota_record(USRQUOTA, UID).is_ok());
}
