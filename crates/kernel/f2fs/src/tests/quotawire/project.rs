//! What a project's own tree reports as free.

use super::*;

// ------------------------------- what a project's own tree reports as free

use crate::quota::uapi::PRJQUOTA;

const PROJID: u32 = 55;
const PRJ_QUOTA_INO: u32 = 10;
const PRJ_FILE_INO: u32 = 11;
const PRJ_PLAIN_INO: u32 = 12;

/// The user fixture's file, marked as the PROJECT kind.
///
/// A quota file's contents are identical whichever identity it accounts for;
/// the magic is the only thing that says which of the three it is, so it is
/// the only thing this changes.
fn project_file(bhard_units: u64, ihard: u64) -> Vec<u8> {
    let mut f = qi::user_file(PROJID, bhard_units, ihard);
    let magic = crate::quota::uapi::MAGIC[PRJQUOTA].to_le_bytes();
    f[crate::quota::uapi::DQH_MAGIC..][..magic.len()].copy_from_slice(&magic);
    f
}

/// The same file, carrying a usage this kernel's own charging could never
/// write: every charge here is a whole block, and a quota file written by
/// another implementation is not so constrained.
fn project_file_with_usage(bhard_units: u64, curspace: u64) -> Vec<u8> {
    let mut f = project_file(bhard_units, 0);
    let mut info = crate::quota::info::parse(&f, PRJQUOTA).unwrap();
    let mut d = crate::quota::tree::read(&f, &info, PROJID).unwrap().expect("the planted record");
    d.curspace = curspace;
    crate::quota::tree::write_or_create(&mut f, &mut info, PROJID, &d).unwrap();
    crate::quota::info::store(&mut f, &info).unwrap();
    f
}

/// An image that accounts projects, holding one file inside `PROJID` and one
/// outside every project.
fn project_image(bhard_units: u64, ihard: u64) -> Vec<u8> {
    project_image_from(project_file(bhard_units, ihard))
}

/// The same, around a quota file the caller built. # C: O(file bytes)
fn project_image_from(file: Vec<u8>) -> Vec<u8> {
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_QUOTA_INO | crate::flags::FEATURE_PRJQUOTA;
    b.qf_ino[PRJQUOTA] = PRJ_QUOTA_INO;
    let blocks: Vec<(u64, Vec<u8>)> =
        file.chunks(BLKSIZE).enumerate().map(|(i, c)| (i as u64, c.to_vec())).collect();
    nodes::add_sparse_file(&mut b, PRJ_QUOTA_INO, file.len() as u64, &blocks);
    // A file that inherits a project, which is the only kind of object the
    // narrowing applies to.
    let mut s = test_image::nodes::Spec::file(PRJ_FILE_INO);
    s.flags = crate::flags::F2FS_PROJINHERIT_FL;
    test_image::nodes::add_sparse_with(&mut b, s, &[]);
    test_image::nodes::patch_inode(&mut b, PRJ_FILE_INO, |blk| {
        blk[crate::uapi::I_PROJID..crate::uapi::I_PROJID + 4]
            .copy_from_slice(&PROJID.to_le_bytes());
    });
    // A file carrying the SAME project and no inherit flag. Every inode on a
    // project-quota volume carries a project id; only the flag says the
    // object is confined to it, so this is what tells the flag apart from the
    // id — and a test that uses an inode whose project has no limits cannot.
    test_image::nodes::add_sparse_with(&mut b, test_image::nodes::Spec::file(PRJ_PLAIN_INO), &[]);
    test_image::nodes::patch_inode(&mut b, PRJ_PLAIN_INO, |blk| {
        blk[crate::uapi::I_PROJID..crate::uapi::I_PROJID + 4]
            .copy_from_slice(&PROJID.to_le_bytes());
    });
    b.finish()
}

/// The mounted filesystem, its superblock operations, and the two inodes.
fn project_fs(bhard_units: u64, ihard: u64, enforce: bool)
    -> (alloc::sync::Arc<crate::mount::F2fs>, crate::mount::sb::F2fsSuperOps) {
    project_fs_on(project_image(bhard_units, ihard), enforce)
}

/// The same, over an image the caller built. # C: O(image bytes)
fn project_fs_on(bytes: Vec<u8>, enforce: bool)
    -> (alloc::sync::Arc<crate::mount::F2fs>, crate::mount::sb::F2fsSuperOps) {
    let blocks = bytes.len() as u64 / BLKSIZE as u64;
    let dev: alloc::sync::Arc<block::MemDisk<sync::TaskList>> =
        block::MemDisk::new(BLKSIZE as u32, blocks);
    let mut req = block::BlockRequest::new_write(0, blocks as u32, bytes);
    block::BlockDevice::submit_sync(&*dev, &mut req).expect("device write");
    let mut o = Options::defaults();
    o.prjquota = enforce;
    let fs = crate::mount::F2fs::open_with(dev, "/dev/fake", true, o).expect("mount");
    let ops = crate::mount::sb::F2fsSuperOps { fs: alloc::sync::Arc::clone(&fs) };
    (fs, ops)
}

/// The five counts the narrowing can move. `SbStatFs` carries no equality of
/// its own, and comparing the counts is what these tests mean anyway.
fn counts(s: &vfs::superblock::SbStatFs) -> [u64; 5] {
    [s.f_blocks, s.f_bfree, s.f_bavail, s.f_files, s.f_ffree]
}

/// The inode the narrowing is asked about.
fn inode_of(fs: &alloc::sync::Arc<crate::mount::F2fs>, ino: u32) -> vfs::InodeRef {
    crate::mount::node::node_inode(alloc::sync::Arc::clone(fs), ino).expect("inode")
}

#[test]
fn a_file_inside_a_project_reports_the_projects_limits_not_the_volumes() {
    // Four blocks' worth of project, on a volume with far more than that.
    let limit_units = 4 * (BLKSIZE as u64 / crate::quota::uapi::SPACE_UNIT);
    let (fs, ops) = project_fs(limit_units, 3, true);
    let whole = vfs::superblock::SuperOps::statfs(&ops).unwrap();
    let narrow =
        vfs::superblock::SuperOps::statfs_at(&ops, &inode_of(&fs, PRJ_FILE_INO)).unwrap();

    assert!(whole.f_blocks > 4, "the volume must be bigger than the project for this to mean anything");
    assert_eq!(narrow.f_blocks, 4, "the project's size, in blocks");
    assert_eq!(narrow.f_bfree, 4, "nothing of it is used yet");
    assert_eq!(narrow.f_bavail, 4, "and none of it is held back from an ordinary caller");
    assert_eq!(narrow.f_files, 3, "the project's inode limit");
    assert_eq!(narrow.f_ffree, 3);
    // Everything that is not a count of the project is the volume's own.
    assert_eq!(narrow.f_bsize, whole.f_bsize);
    assert_eq!(narrow.f_fsid, whole.f_fsid);
    assert_eq!(narrow.f_namelen, whole.f_namelen);
}

#[test]
fn what_the_project_has_used_comes_off_what_it_reports_free() {
    let limit_units = 4 * (BLKSIZE as u64 / crate::quota::uapi::SPACE_UNIT);
    let (fs, ops) = project_fs(limit_units, 3, true);
    // One block of the four, charged the way an ordinary write charges it:
    // the file carries the project, so the write is the project's.
    fs.volume.lock().write_file(PRJ_FILE_INO, 0, &vec![7u8; BLKSIZE]).unwrap();
    assert_eq!(
        fs.volume.lock().quota_record(PRJQUOTA, PROJID).unwrap().curspace,
        BLKSIZE as u64,
        "the write was not charged to the project at all",
    );
    let narrow =
        vfs::superblock::SuperOps::statfs_at(&ops, &inode_of(&fs, PRJ_FILE_INO)).unwrap();
    assert_eq!(narrow.f_blocks, 4, "the size does not move as it fills");
    assert_eq!(narrow.f_bfree, 3, "one of the four is gone");
    assert_eq!(narrow.f_bavail, 3);
}

#[test]
fn a_mount_that_does_not_enforce_projects_reports_the_volumes_counts() {
    // The record and the flag are both there; only the enforcement is not,
    // and a limit nobody applies must not shrink what anybody is told.
    let limit_units = 4 * (BLKSIZE as u64 / crate::quota::uapi::SPACE_UNIT);
    let (fs, ops) = project_fs(limit_units, 3, false);
    let whole = vfs::superblock::SuperOps::statfs(&ops).unwrap();
    let narrow =
        vfs::superblock::SuperOps::statfs_at(&ops, &inode_of(&fs, PRJ_FILE_INO)).unwrap();
    assert_eq!(counts(&narrow), counts(&whole));
    assert!(whole.f_blocks > 4);
}

#[test]
fn a_file_that_inherits_no_project_is_answered_for_the_whole_volume() {
    let limit_units = 4 * (BLKSIZE as u64 / crate::quota::uapi::SPACE_UNIT);
    let (fs, ops) = project_fs(limit_units, 3, true);
    let whole = vfs::superblock::SuperOps::statfs(&ops).unwrap();
    // This inode names the very project the file beside it is confined to,
    // and carries no inherit flag. It must be answered for the whole volume:
    // the id says which project the object's allocations are charged to, the
    // flag says the object lives inside it.
    let plain = vfs::superblock::SuperOps::statfs_at(&ops, &inode_of(&fs, PRJ_PLAIN_INO)).unwrap();
    assert_eq!(counts(&plain), counts(&whole));
    assert!(whole.f_blocks > 4, "the project's limit would be visible if it were applied");
    // And so must an inode that names no project at all.
    let root = vfs::superblock::SuperOps::statfs_at(&ops, &inode_of(&fs, ROOT_INO)).unwrap();
    assert_eq!(counts(&root), counts(&whole));
}

#[test]
fn a_project_with_no_limit_reports_the_volume_rather_than_nothing_free() {
    // A project that exists and is unlimited must not read as a full
    // filesystem: zero free is what a caller acts on, and it would be wrong.
    let (fs, ops) = project_fs(0, 0, true);
    let whole = vfs::superblock::SuperOps::statfs(&ops).unwrap();
    let narrow =
        vfs::superblock::SuperOps::statfs_at(&ops, &inode_of(&fs, PRJ_FILE_INO)).unwrap();
    assert_eq!(counts(&narrow), counts(&whole));
    assert!(narrow.f_bfree > 0);
}

#[test]
fn a_project_limited_to_less_than_one_block_narrows_nothing() {
    // The limit rounds down to no blocks at all. Reporting a filesystem of
    // zero blocks with zero free says the write will fail for want of space
    // when the truthful answer is the volume's; the quota refuses the write
    // itself, which is where the refusal belongs.
    let (fs, ops) = project_fs(1, 0, true);
    let whole = vfs::superblock::SuperOps::statfs(&ops).unwrap();
    let narrow =
        vfs::superblock::SuperOps::statfs_at(&ops, &inode_of(&fs, PRJ_FILE_INO)).unwrap();
    assert_eq!(narrow.f_blocks, whole.f_blocks);
    assert_eq!(narrow.f_bfree, whole.f_bfree);
    assert_eq!(narrow.f_bavail, whole.f_bavail);
}

#[test]
fn a_limit_and_a_usage_that_are_not_whole_blocks_round_the_way_the_format_does() {
    // Both sides are rounded to whole blocks BEFORE they are subtracted. A
    // limit is stored in units a block is not a multiple of, and a file
    // another implementation wrote can carry a usage that is not a whole
    // block either; subtracting first and rounding after reports a block
    // fewer free than the project may still use.
    let per_block = BLKSIZE as u64 / crate::quota::uapi::SPACE_UNIT;
    let file = project_file_with_usage(4 * per_block + 1, 2 * crate::quota::uapi::SPACE_UNIT);
    let (fs, ops) = project_fs_on(project_image_from(file), true);
    let narrow =
        vfs::superblock::SuperOps::statfs_at(&ops, &inode_of(&fs, PRJ_FILE_INO)).unwrap();
    assert_eq!(narrow.f_blocks, 4, "four whole blocks out of a limit of four and a quarter");
    assert_eq!(narrow.f_bfree, 4, "half a block used is no whole block used");
    assert_eq!(narrow.f_bavail, 4);
}
