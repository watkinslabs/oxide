use super::*;

#[test]
fn final_rmdir_quota_release_failure_preserves_namespace_and_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    m.state().mkdir_at(b"/rmdir-quota-release-fail", 0o755).expect("mkdir");
    let dir = m.state().lookup_inode_any(b"/rmdir-quota-release-fail").expect("lookup dir");
    let ino = dir.ino() as u32;
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_root = m.state().mount.read_inode(2).expect("root before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    drop(dir);

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    let err = m.state().rmdir_at(b"/rmdir-quota-release-fail").expect_err("quota release failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/rmdir-quota-release-fail"), Some(ino));
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    let after_root = m.state().mount.read_inode(2).expect("root after");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_root.links_count, before_root.links_count);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn vfs_final_rmdir_inode_write_failure_preserves_namespace_and_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = sb.s_root_inode().expect("root inode");
    let dir = root.mkdir("iop-rmdir-rollback-quota", 0o755, &CreateCtx::root()).expect("mkdir");
    let ino = dir.ino() as u32;
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_root = m.state().mount.read_inode(2).expect("root before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_inode_write_for_tests();
    let err = root.rmdir("iop-rmdir-rollback-quota").expect_err("injected rmdir inode write failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/iop-rmdir-rollback-quota"), Some(ino));
    assert_eq!(root.lookup("iop-rmdir-rollback-quota").expect("dir remains").ino(), dir.ino());
    assert_eq!(dir.nlink(), before_raw.links_count.into(), "failed rmdir keeps cached link count");
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    let after_root = m.state().mount.read_inode(2).expect("root after");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_root.links_count, before_root.links_count);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn vfs_final_rmdir_quota_release_failure_preserves_namespace_and_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = sb.s_root_inode().expect("root inode");
    let dir = root.mkdir("iop-rmdir-quota-release-fail", 0o755, &CreateCtx::root()).expect("mkdir");
    let ino = dir.ino() as u32;
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_root = m.state().mount.read_inode(2).expect("root before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    let err = root.rmdir("iop-rmdir-quota-release-fail").expect_err("quota release failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/iop-rmdir-quota-release-fail"), Some(ino));
    assert_eq!(root.lookup("iop-rmdir-quota-release-fail").expect("dir remains").ino(), dir.ino());
    assert_eq!(dir.nlink(), before_raw.links_count.into(), "failed rmdir keeps cached link count");
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    let after_root = m.state().mount.read_inode(2).expect("root after");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_root.links_count, before_root.links_count);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

