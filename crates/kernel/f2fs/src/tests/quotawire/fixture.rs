//! The volumes, images and records the quota call-site tests are built on.
//!
//! One fixture per shape the tests need: a volume that accounts users, an
//! image that accounts projects, and the readers that say what a record
//! currently holds.

use super::*;

pub(super) const NOW: (u64, u32) = (1_800_000_000, 0);
pub(super) const UID: u32 = 4242;
pub(super) const QUOTA_INO: u32 = 9;

pub(super) fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: UID, gid: UID, rdev: 0, now: NOW }
}

/// A volume whose user-quota file holds one record for `UID`.
pub(super) fn with_quota(bhard_units: u64, ihard: u64, enforce: bool) -> Volume<MemImage> {
    let file = qi::user_file(UID, bhard_units, ihard);
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_QUOTA_INO;
    b.qf_ino[USRQUOTA] = QUOTA_INO;
    let blocks: Vec<(u64, Vec<u8>)> =
        file.chunks(BLKSIZE).enumerate().map(|(i, c)| (i as u64, c.to_vec())).collect();
    nodes::add_sparse_file(&mut b, QUOTA_INO, file.len() as u64, &blocks);
    let mut o = Options::defaults();
    o.usrquota = enforce;
    let mut v = b.mount_opts(o).unwrap();
    v.set_clock(NOW.0);
    v
}

pub(super) fn space(v: &mut Volume<MemImage>) -> u64 {
    v.quota_record(USRQUOTA, UID).unwrap().curspace
}

pub(super) fn inodes(v: &mut Volume<MemImage>) -> u64 {
    v.quota_record(USRQUOTA, UID).unwrap().curinodes
}

/// An identity the fixture's quota file holds no record for.
pub(super) const OTHER: u32 = 7777;

/// A new file owned by `uid`. # C: O(1)
pub(super) fn spec_of(uid: u32) -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid, gid: uid, rdev: 0, now: NOW }
}

/// A volume that accounts users AND carries the compression feature, holding
/// one compressed file owned by `UID`.
///
/// The two features are independent bits and nothing in the charging path
/// knows about compression, which is exactly why the pair needs a fixture: a
/// charge computed from the cluster's WIDTH rather than from the blocks it
/// actually occupies would be invisible on a volume with no quota.
/// # C: O(1 image)
pub(super) fn with_compressed_quota(algo: u8, log: u8, bhard_units: u64)
    -> (Volume<MemImage>, u32) {
    let file = qi::user_file(UID, bhard_units, 0);
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_QUOTA_INO | crate::flags::FEATURE_COMPRESSION;
    b.qf_ino[USRQUOTA] = QUOTA_INO;
    let blocks: Vec<(u64, Vec<u8>)> =
        file.chunks(BLKSIZE).enumerate().map(|(i, c)| (i as u64, c.to_vec())).collect();
    nodes::add_sparse_file(&mut b, QUOTA_INO, file.len() as u64, &blocks);
    let mut o = Options::defaults();
    o.usrquota = true;
    let mut v = b.mount_opts(o).unwrap();
    v.set_clock(NOW.0);
    let ino = v.create(ROOT_INO, b"c", &spec(), None).unwrap();
    v.stamp_inode(ino, |bytes| {
        let f = crate::uapi::le32(bytes, crate::uapi::I_FLAGS).unwrap_or(0)
            | crate::flags::F2FS_COMPR_FL;
        crate::volume::dnode::put32(bytes, crate::uapi::I_FLAGS, f);
        bytes[crate::uapi::I_COMPRESS_ALGORITHM] = algo;
        bytes[crate::uapi::I_LOG_CLUSTER_SIZE] = log;
    })
    .unwrap();
    (v, ino)
}

/// A plain file owned by the same identity, for the differential the
/// compressed tests turn on. # C: O(1)
pub(super) fn plain_file(v: &mut Volume<MemImage>) -> u32 {
    v.create(ROOT_INO, b"p", &spec(), None).unwrap()
}
