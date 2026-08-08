//! `create`/`tmpfile` must instantiate the VFS inode from the struct they just
//! wrote, never by reading the slot back off disk — Linux `ext4_create` hands
//! the live inode straight to dentry instantiation and never re-reads it.
//!
//! The round-trip was the boot's
//! `[NAMEI] openat-create ".../user-1000.journal" err=5`: `create_file` had
//! SUCCEEDED, then `wrap_file`'s `read_inode(...).ok()?` failed and every
//! backend error collapsed into a bare `EIO` from a create that worked.
//!
//! Each test arms `fail_next_inode_read_for_tests` — the control that can
//! actually fail. `readback_control_still_fails` proves the injection bites, so
//! the passing cases are not vacuous.

extern crate alloc;
mod common;
use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const SECTOR: u32 = 512;

fn mount_mini() -> (Arc<ext4::rootfs::Ext4Mount>, Arc<vfs::SuperBlock>) {
    common::boot_hosted_pmm();
    let bytes = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/mini.img")).expect("mini.img");
    let cap = (bytes.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: bytes, ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("open mini.img");
    let fs: Arc<dyn vfs::fs::FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, 0xE471_0DB2, String::from("ext4"));
    (m, sb)
}

/// POSITIVE CONTROL: the injection really does break `read_inode`, so a
/// create that survives it below is surviving something real.
#[test]
fn readback_control_still_fails() {
    let (m, _sb) = mount_mini();
    let st = m.state();
    let root_ino = st.mount.lookup_path(b"/").unwrap_or(2);
    let ino = st.mount.create_file(root_ino, b"control.dat", 0o644, 0, 0).expect("create_file");
    st.mount.fail_next_inode_read_for_tests();
    assert!(st.mount.read_inode(ino).is_err(), "injection must break read_inode");
    // And the read-back-based wrapper folds that into a `None` — the old
    // `create` returned `EIO` from exactly this.
    st.mount.fail_next_inode_read_for_tests();
    assert!(st.wrap_file(ino).is_none(), "wrap_file collapses a failed read to None");
}

/// The regression: `create` must NOT consult the inode table for what it just
/// wrote, so an unreadable slot cannot turn a successful create into `EIO`.
#[test]
fn create_survives_failing_inode_readback() {
    let (m, _sb) = mount_mini();
    let st = m.state();
    let dir = st.lookup_inode_any(b"/").expect("root inode");
    let ctx = vfs::CreateCtx::root();
    st.mount.fail_next_inode_read_for_tests();
    let created = dir.create_child("user-1000.journal", 0o640, &ctx)
        .expect("create must not depend on reading the inode back");
    assert_eq!(created.i_mode() & 0o7777, 0o640, "mode comes from the struct just written");
    assert!(matches!(created.file_type(), vfs::FileType::Regular), "S_IFREG from init_inode");
    assert_eq!(created.nlink(), 1, "a linked create starts at nlink=1");
}

/// The invariant stated directly: instantiating the VFS inode from a create
/// reads the inode table ZERO times. Measured rather than inferred from which
/// injected fault fired first — `orphan_add` legitimately reads the inode it
/// pushes, so a one-shot fault around `tmpfile` proves nothing on its own.
#[test]
fn wrap_of_a_created_inode_reads_nothing() {
    let (m, _sb) = mount_mini();
    let st = m.state();
    for (label, made) in [
        ("create", st.mount.create_file_inode(2, b"wrapped.dat", 0o640, 0, 0).expect("create_file_inode")),
        ("tmpfile", st.mount.create_anonymous_inode(2, 0o600, 0, 0).expect("create_anonymous_inode")),
    ] {
        let (ino, node) = made;
        st.mount.reset_inode_read_count_for_tests();
        let wrapped = st.wrap_created_file(ino, &node);
        assert_eq!(st.mount.inode_read_count_for_tests(), 0, "{label}: wrap must not read the inode table");
        assert_eq!(wrapped.i_mode() & 0o7777, node.mode & 0o7777, "{label}: mode from the written struct");
        // Same measurement for the read-back wrapper proves the counter works.
        st.mount.reset_inode_read_count_for_tests();
        let _ = st.wrap_file(ino);
        assert_eq!(st.mount.inode_read_count_for_tests(), 1, "{label}: control — wrap_file does read");
    }
}

/// `mkdir` shared the read-back — it was the boot's other journald symptom,
/// `mkdir /var/log/journal/<id> err=5`.
#[test]
fn mkdir_survives_failing_inode_readback() {
    let (m, _sb) = mount_mini();
    let st = m.state();
    let dir = st.lookup_inode_any(b"/").expect("root inode");
    st.mount.fail_next_inode_read_for_tests();
    let made = dir.mkdir("journal", 0o755, &vfs::CreateCtx::root())
        .expect("mkdir must not depend on reading the inode back");
    assert!(matches!(made.file_type(), vfs::FileType::Directory), "S_IFDIR from init_inode");
    assert_eq!(made.nlink(), 2, "a fresh directory has `.` plus its parent entry");
    assert!(made.size() > 0, "size is the `.`/`..` block create_dir wrote, not 0");
}

/// `O_TMPFILE` end to end: the anonymous inode surfaces with the mode and
/// nlink `init_inode` wrote, without a read-back.
#[test]
fn tmpfile_instantiates_from_the_written_inode() {
    let (m, _sb) = mount_mini();
    let st = m.state();
    let dir = st.lookup_inode_any(b"/").expect("root inode");
    let tmp = dir.tmpfile(0o600, &vfs::CreateCtx::root()).expect("tmpfile");
    assert_eq!(tmp.i_mode() & 0o7777, 0o600);
    assert_eq!(tmp.nlink(), 0, "an anonymous inode starts unlinked");
}

/// The created inode must still be the real on-disk one: same ino, and readable
/// once the injected fault is spent. Guards against "wrap a fabricated inode".
#[test]
fn created_inode_matches_disk() {
    let (m, _sb) = mount_mini();
    let st = m.state();
    let dir = st.lookup_inode_any(b"/").expect("root inode");
    let created = dir.create_child("real.dat", 0o640, &vfs::CreateCtx::root()).expect("create");
    let ino = st.lookup_child_ino(2, "real.dat").expect("dirent for the new file");
    let disk = st.mount.read_inode(ino).expect("inode readable on disk");
    assert_eq!(disk.mode & 0o7777, 0o640, "on-disk mode matches what create reported");
    assert!(disk.is_reg(), "on-disk type is S_IFREG");
    assert_eq!(disk.links_count, 1);
    assert_eq!(created.ino(), st.wrap_file(ino).expect("wrap").ino(), "same VFS identity");
}
