use super::*;

#[test]
fn same_path_rename_noops_without_releasing_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let file = m.state().create_at(b"/same-rename.txt", 0o644).expect("create file");
    let ino = file.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0x51; (bs * 2) as usize]).expect("seed file data");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before direct rename");
    let before_map = m.state().mount.extent_map(ino).expect("map before direct rename");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before direct rename");
    drop(file);

    m.state().rename_at(b"/same-rename.txt", b"/same-rename.txt").expect("same-path direct rename");

    assert_eq!(m.state().lookup_path(b"/same-rename.txt"), Some(ino));
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after direct rename");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(m.state().mount.extent_map(ino).expect("map after direct rename"), before_map);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after direct rename");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);

    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota for vfs rename");
    let root = sb.s_root_inode().expect("root inode");
    let file = root.create_child("iop-same-rename.txt", 0o644, &CreateCtx::root()).expect("create vfs file");
    let ino = file.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0x52; (bs * 2) as usize]).expect("seed vfs file data");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before vfs rename");
    let before_map = m.state().mount.extent_map(ino).expect("map before vfs rename");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before vfs rename");

    root.rename_child("iop-same-rename.txt", &root, "iop-same-rename.txt", 0, &CreateCtx::root())
        .expect("same-path vfs rename");

    assert_eq!(m.state().lookup_path(b"/iop-same-rename.txt"), Some(ino));
    assert_eq!(root.lookup("iop-same-rename.txt").expect("file remains").ino(), file.ino());
    assert_eq!(file.nlink(), before_raw.links_count.into());
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after vfs rename");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(m.state().mount.extent_map(ino).expect("map after vfs rename"), before_map);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after vfs rename");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn final_unlink_inode_write_failure_preserves_namespace_and_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/unlink-rollback-quota.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    m.state().mount.write_at(ino, 0, &vec![0xA9; (bs * 2) as usize]).expect("seed file data");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_map = m.state().mount.extent_map(ino).expect("extent map before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    assert_eq!(before_q.dqb_curinodes, 1);
    assert_eq!(before_q.dqb_curspace, before_raw.i_blocks as u64 * 512);
    drop(inode);

    m.state().mount.fail_next_inode_write_for_tests();
    let err = m.state().unlink_at(b"/unlink-rollback-quota.txt").expect_err("injected unlink inode write failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/unlink-rollback-quota.txt"), Some(ino));
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(m.state().mount.extent_map(ino).expect("extent map after"), before_map);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

/// A failed quota release CANNOT roll an unlink back, and this test used to
/// assert that it did (EIO returned, dirent preserved). That expectation was
/// never Linux: unlink calls no quota-release function at
/// all — it deletes the entry, drops the link count and orphans the inode. The
/// release happens only at inode-free time, reached from eviction on the
/// last reference, and that free path returns `void` — by then the
/// name is long gone and there is nothing to undo.
///
/// The real contract: the unlink succeeds, and because nothing holds this
/// inode the eviction runs inline, where `RootfsState::free_orphan_inode`
/// releases through `release_existing_inode_retry` — which absorbs exactly one
/// failed `mark_dirty`. So the accounting still lands and the blocks and the
/// inode slot both come back.
#[test]
fn final_unlink_quota_release_failure_is_retried_at_eviction() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let base_free_inodes = m.state().mount.state_free_inodes();
    let base_q = vfs::quota_getquota(&sb, qid).expect("quota before create");

    let inode = m.state().create_at(b"/unlink-quota-release-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let free_blocks_before_data = m.state().mount.state_free_blocks();
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xC3; (bs * 2) as usize]).expect("seed file data");
    let charged = m.state().mount.read_inode(ino).expect("raw before").i_blocks as u64 * 512;
    assert_ne!(charged, 0, "the victim must own blocks for the space release to mean anything");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    assert_eq!(before_q.dqb_curinodes, base_q.dqb_curinodes + 1);
    assert_eq!(before_q.dqb_curspace, base_q.dqb_curspace + charged);
    drop(inode);

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    m.state().unlink_at(b"/unlink-quota-release-fail.txt")
        .expect("unlink succeeds — no dquot call can fail it");

    assert_eq!(m.state().lookup_path(b"/unlink-quota-release-fail.txt"), None, "the name is gone");
    assert_eq!(m.state().mount.state_free_blocks(), free_blocks_before_data, "eviction gave the blocks back");
    assert_eq!(m.state().mount.state_free_inodes(), base_free_inodes, "eviction gave the inode slot back");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, base_q.dqb_curinodes, "the retried release still lands");
    assert_eq!(after_q.dqb_curspace, base_q.dqb_curspace);
}

#[test]
fn vfs_final_unlink_inode_write_failure_preserves_namespace_and_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = sb.s_root_inode().expect("root inode");
    let file = root.create_child("iop-unlink-rollback-quota.txt", 0o644, &CreateCtx::root()).expect("create file");
    let ino = file.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    m.state().mount.write_at(ino, 0, &vec![0xB1; (bs * 2) as usize]).expect("seed file data");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_map = m.state().mount.extent_map(ino).expect("extent map before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_inode_write_for_tests();
    let err = root.unlink_child("iop-unlink-rollback-quota.txt").expect_err("injected unlink inode write failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/iop-unlink-rollback-quota.txt"), Some(ino));
    assert_eq!(root.lookup("iop-unlink-rollback-quota.txt").expect("cached source remains").ino(), file.ino());
    assert_eq!(file.nlink(), 1, "failed unlink keeps cached link count");
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(m.state().mount.extent_map(ino).expect("extent map after"), before_map);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

/// Same correction as [`final_unlink_quota_release_failure_is_retried_at_eviction`]
/// through `i_op->unlink`, and one step further: the test holds `file`, so the
/// eviction is DEFERRED. Unlink removes the name
/// and orphans the inode without touching quota; the armed `mark_dirty`
/// failure therefore cannot reach the unlink at all, and only fires later,
/// during eviction's inode-free/quota-release step, where
/// `release_existing_inode_retry` absorbs it.
#[test]
fn vfs_final_unlink_quota_release_failure_is_retried_at_eviction() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = sb.s_root_inode().expect("root inode");
    let base_free_inodes = m.state().mount.state_free_inodes();
    let base_q = vfs::quota_getquota(&sb, qid).expect("quota before create");

    let file = root.create_child("iop-unlink-quota-release-fail.txt", 0o644, &CreateCtx::root()).expect("create file");
    let ino = file.ino() as u32;
    let free_blocks_before_data = m.state().mount.state_free_blocks();
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xD4; (bs * 2) as usize]).expect("seed file data");
    let charged = m.state().mount.read_inode(ino).expect("raw before").i_blocks as u64 * 512;
    assert_ne!(charged, 0);
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    assert_eq!(before_q.dqb_curinodes, base_q.dqb_curinodes + 1);
    assert_eq!(before_q.dqb_curspace, base_q.dqb_curspace + charged);

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    root.unlink_child("iop-unlink-quota-release-fail.txt")
        .expect("unlink succeeds — no dquot call can fail it");

    assert_eq!(m.state().lookup_path(b"/iop-unlink-quota-release-fail.txt"), None, "the name is gone");
    assert!(root.lookup("iop-unlink-quota-release-fail.txt").is_err(), "the dcache entry is gone too");
    assert_eq!(file.nlink(), 0, "the final unlink zeroed the cached link count");
    // Held-across-unlink invariant: nothing is freed while `file` lives.
    assert_eq!(m.state().mount.state_free_inodes(), base_free_inodes - 1, "the inode slot is still in use");
    let held_q = vfs::quota_getquota(&sb, qid).expect("quota while held");
    assert_eq!(held_q.dqb_curinodes, before_q.dqb_curinodes, "unlink-while-held keeps the inode charged");
    assert_eq!(held_q.dqb_curspace, before_q.dqb_curspace, "unlink-while-held keeps the space charged");

    vfs::file::iput(file);

    assert_eq!(m.state().mount.state_free_blocks(), free_blocks_before_data, "eviction gave the blocks back");
    assert_eq!(m.state().mount.state_free_inodes(), base_free_inodes, "eviction gave the inode slot back");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after eviction");
    assert_eq!(after_q.dqb_curinodes, base_q.dqb_curinodes, "the retried release still lands");
    assert_eq!(after_q.dqb_curspace, base_q.dqb_curspace);
}

