use super::*;

/// A regular-file rename victim follows the unlink contract: overwrite
/// decrements its link count and defers quota release until eviction.

#[test]
fn rename_overwrite_quota_release_failure_is_retried_at_victim_eviction() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let src = m.state().create_at(b"/rename-quota-src.txt", 0o644).expect("create source");
    let dst = m.state().create_at(b"/rename-quota-dst.txt", 0o644).expect("create dest");
    let src_ino = src.ino() as u32;
    let dst_ino = dst.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(dst_ino, 0, &vec![0xE5; (bs * 2) as usize]).expect("seed victim data");
    let victim_space = m.state().mount.read_inode(dst_ino).expect("raw dest before").i_blocks as u64 * 512;
    assert_ne!(victim_space, 0);
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    drop(src);
    drop(dst);

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    m.state().rename_at(b"/rename-quota-src.txt", b"/rename-quota-dst.txt")
        .expect("rename succeeds — a regular victim's release is not on the rename path");

    assert_eq!(m.state().lookup_path(b"/rename-quota-src.txt"), None, "the source name is gone");
    assert_eq!(m.state().lookup_path(b"/rename-quota-dst.txt"), Some(src_ino), "the destination names the source");
    assert!(m.state().mount.read_inode(dst_ino).map(|i| i.links_count).unwrap_or(0) == 0,
        "the replaced victim lost its last link");
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks + (victim_space / bs),
        "the victim's blocks came back at eviction");
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes + 1,
        "the victim's inode slot came back at eviction");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes - 1, "the retried release still lands");
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace - victim_space);
}

/// The path that genuinely still pre-releases and rolls back: a DIRECTORY
/// victim. `Mount::rmdir` frees a directory outright (a directory has no
/// open-fd data to preserve), so its charge is released up front — and a
/// failure there aborts the rename with the namespace and the quota intact,
/// exactly like `Ext4StatInodeOps::rmdir`. Contrast with the regular-file
/// victim above, which is merely orphaned.
#[test]
fn rename_overwrite_directory_victim_quota_release_failure_rolls_back() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    m.state().mkdir_at(b"/rename-quota-dir-src", 0o755).expect("mkdir source");
    m.state().mkdir_at(b"/rename-quota-dir-dst", 0o755).expect("mkdir dest");
    let src_ino = m.state().lookup_path(b"/rename-quota-dir-src").expect("source ino");
    let dst_ino = m.state().lookup_path(b"/rename-quota-dir-dst").expect("dest ino");
    let before_dst_raw = m.state().mount.read_inode(dst_ino).expect("raw dest before");
    let before_root = m.state().mount.read_inode(2).expect("root before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    let err = m.state().rename_at(b"/rename-quota-dir-src", b"/rename-quota-dir-dst")
        .expect_err("up-front directory-victim release failure aborts the rename");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/rename-quota-dir-src"), Some(src_ino));
    assert_eq!(m.state().lookup_path(b"/rename-quota-dir-dst"), Some(dst_ino));
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_dst_raw = m.state().mount.read_inode(dst_ino).expect("raw dest after");
    assert_eq!(after_dst_raw.links_count, before_dst_raw.links_count);
    assert_eq!(after_dst_raw.size, before_dst_raw.size);
    assert_eq!(after_dst_raw.i_blocks, before_dst_raw.i_blocks);
    assert_eq!(m.state().mount.read_inode(2).expect("root after").links_count, before_root.links_count);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

/// `i_op->rename` over a REGULAR-file victim that the test still HOLDS. Same
/// correction as the path-based case — rename-overwrite only decrements the
/// link count and orphans the victim, releasing no quota
/// — plus the deferral: with `dst` alive the victim's blocks and charge outlive
/// the rename, and the armed `mark_dirty` failure only reaches
/// inode-free at the eviction the last `iput` triggers,
/// where `release_existing_inode_retry` absorbs it.
#[test]
fn vfs_rename_overwrite_quota_release_failure_is_retried_at_victim_eviction() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = sb.s_root_inode().expect("root inode");
    let src = root.create_child("iop-rename-quota-src.txt", 0o644, &CreateCtx::root()).expect("create source");
    let dst = root.create_child("iop-rename-quota-dst.txt", 0o644, &CreateCtx::root()).expect("create dest");
    let src_ino = src.ino() as u32;
    let dst_ino = dst.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(dst_ino, 0, &vec![0xF6; (bs * 2) as usize]).expect("seed victim data");
    let victim_space = m.state().mount.read_inode(dst_ino).expect("raw dest before").i_blocks as u64 * 512;
    assert_ne!(victim_space, 0);
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    root.rename_child("iop-rename-quota-src.txt", &root, "iop-rename-quota-dst.txt", 0, &CreateCtx::root())
        .expect("rename succeeds — a regular victim's release is not on the rename path");

    assert_eq!(m.state().lookup_path(b"/iop-rename-quota-src.txt"), None, "the source name is gone");
    assert_eq!(m.state().lookup_path(b"/iop-rename-quota-dst.txt"), Some(src_ino), "the destination names the source");
    assert_eq!(dst.nlink(), 0, "the replaced victim lost its last link");
    // Held-across-rename invariant: the victim is orphaned, not freed.
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks, "the victim's blocks survive while held");
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes, "the victim's inode slot survives while held");
    let held_q = vfs::quota_getquota(&sb, qid).expect("quota while victim held");
    assert_eq!(held_q.dqb_curinodes, before_q.dqb_curinodes, "the victim stays charged while held");
    assert_eq!(held_q.dqb_curspace, before_q.dqb_curspace);

    vfs::file::iput(dst);

    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks + (victim_space / bs),
        "eviction gave the victim's blocks back");
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes + 1,
        "eviction gave the victim's inode slot back");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after eviction");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes - 1, "the retried release still lands");
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace - victim_space);
    drop(src);
}
