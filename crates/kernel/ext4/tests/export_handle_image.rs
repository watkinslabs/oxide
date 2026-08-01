//! `s_export_op` on a REAL ext4 image — the backend half of
//! `open_by_handle_at(2)` (slot 304).
//!
//! Three properties the generic (inode-cache-only) default cannot provide, and
//! which no hosted stub can prove:
//!
//!   1. An inode EVICTED from the cache still resolves, because the backend
//!      re-reads it from the filesystem. Before this, a handle went stale the
//!      moment the last opener closed the file.
//!   2. A handle carries the on-disk `i_generation`, and a mismatch is refused
//!      — so a reallocated inode number cannot be opened through the old file's
//!      handle.
//!   3. A connectable handle reconnects: the decoded non-directory comes back
//!      under its PARENT with its real NAME, not as an anonymous alias.

extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::superblock::next_anon_dev;
use vfs::{InodeRef, SuperBlock};

const IMAGE: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;

fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    disk
}

/// Mount the image and realize its superblock, as the mount engine would.
fn mount() -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    common::boot_hosted_pmm();
    let m = ext4::rootfs::Ext4Mount::open(build_disk()).unwrap();
    let fs: Arc<dyn FileSystem> = m.clone();
    let sb = common::realize_sb(fs.clone(), fs.root(), next_anon_dev(), String::from("ext4-export"));
    (m, sb)
}

/// What slot 303 encodes for a resolved object.
fn handle_of(i: &InodeRef) -> (u64, u32) { (i.ino(), i.i_generation()) }

/// What slot 304 does with it.
fn decode(sb: &Arc<SuperBlock>, h: (u64, u32)) -> Option<InodeRef> {
    sb.s_op.fh_to_dentry(sb, h.0, h.1)
}

/// A newly created ext4 file carries a REAL on-disk generation, not zero. Zero
/// is the "unversioned" wildcard that matches any handle, so a create path that
/// left it unset would silently disable recycle rejection for every file this
/// kernel writes — the field would be stored and never consumed.
#[test]
fn created_inode_gets_a_nonzero_on_disk_generation() {
    let (m, _sb) = mount();
    let st = m.state();
    let a = st.create_at(b"/gen-a", 0o644).expect("create a");
    let b = st.create_at(b"/gen-b", 0o644).expect("create b");
    assert_ne!(a.i_generation(), vfs::export::GENERATION_ANY, "a generation must be stamped");
    assert_ne!(b.i_generation(), vfs::export::GENERATION_ANY);
    assert_ne!(a.i_generation(), b.i_generation(), "two inodes must not share an incarnation");

    // …and it is genuinely ON DISK: a fresh read of the slot reports the same
    // value, so it survives eviction rather than living only in the VFS inode.
    let raw = m.state().mount
        .read_inode(ext4::rootfs::ext4_unwrap_ino(a.ino())).expect("read back");
    assert_eq!(raw.generation, a.i_generation(), "the VFS generation is the on-disk one");
}

/// THE eviction test. A handle is taken, every reference dropped, the inode
/// forgotten from the cache — and the handle still resolves, because the
/// backend re-reads it. The generic default returns `None` here; that
/// difference IS the feature.
#[test]
fn evicted_inode_still_resolves_from_disk() {
    let (m, sb) = mount();
    let st = m.state();
    let handle = {
        let f = st.create_at(b"/evicted.bin", 0o644).expect("create");
        handle_of(&f)
    };
    sb.iforget(handle.0);
    assert!(sb.ilookup(handle.0).is_none(), "precondition: the inode is out of the cache");

    let reopened = decode(&sb, handle).expect("an evicted inode still resolves from disk");
    assert_eq!(reopened.ino(), handle.0);
    assert_eq!(reopened.i_generation(), handle.1, "…as the same incarnation");
}

/// A resident inode resolves to the SAME `Arc` a path walk would return —
/// never a second, parallel copy of one object with its own size and lock.
#[test]
fn resident_inode_resolves_to_the_same_arc() {
    let (m, sb) = mount();
    let st = m.state();
    let f = st.create_at(b"/resident.bin", 0o644).expect("create");
    let reopened = decode(&sb, handle_of(&f)).expect("resolves");
    assert!(Arc::ptr_eq(&f, &reopened), "decode must return the cached inode, not a copy");
}

/// A generation that does not match the on-disk one is refused. This is the
/// rejection that makes a handle safe against inode-number reuse; without it a
/// stale handle opens whatever object inherited the number.
#[test]
fn generation_mismatch_is_refused() {
    let (m, sb) = mount();
    let st = m.state();
    let f = st.create_at(b"/gen-check.bin", 0o644).expect("create");
    let (ino, generation) = handle_of(&f);
    sb.iforget(ino);
    drop(f);

    assert!(decode(&sb, (ino, generation)).is_some(), "the right generation resolves");
    assert!(decode(&sb, (ino, generation.wrapping_add(1))).is_none(),
        "a wrong generation must NOT resolve");
    // The wildcard still matches, so a caller that never had a generation (an
    // older handle, another encoder) is not locked out.
    assert!(decode(&sb, (ino, vfs::export::GENERATION_ANY)).is_some());
}

/// An inode number outside the filesystem, and one whose slot is free, are both
/// unresolvable — the genuinely-gone cases stay ESTALE.
#[test]
fn out_of_range_and_deleted_inodes_stay_stale() {
    let (m, sb) = mount();
    let st = m.state();
    let f = st.create_at(b"/doomed.bin", 0o644).expect("create");
    let handle = handle_of(&f);
    drop(f);
    st.unlink_at(b"/doomed.bin").expect("unlink");
    sb.iforget(handle.0);
    assert!(decode(&sb, handle).is_none(), "a deleted inode does not resolve");

    let beyond = ext4::rootfs::ext4_wrap_ino(m.state().mount.sb.inodes_count + 1);
    assert!(decode(&sb, (beyond, 0)).is_none(), "an inode number past the fs does not resolve");
    assert!(decode(&sb, (0xDEAD_0000_0000_0001, 0)).is_none(), "a foreign ino tag does not resolve");
}

/// `export::get_name` finds the child's name inside its parent by scanning the
/// directory — the step that turns a decoded inode into a NAMED dentry. It must
/// find the real entry and reject an inode that is not a child.
#[test]
fn get_name_finds_the_childs_name_in_its_parent() {
    let (m, sb) = mount();
    let st = m.state();
    st.mkdir_at(b"/reconn", 0o755).expect("mkdir");
    let child = st.create_at(b"/reconn/leaf.txt", 0o644).expect("create child");
    let parent = st.lookup_inode_any(b"/reconn").expect("lookup parent");

    assert_eq!(vfs::export::get_name(&parent, child.ino()).as_deref(), Some("leaf.txt"));
    // A directory that does not contain the inode has no name for it.
    let root = st.lookup_inode_any(b"/").expect("root");
    assert_eq!(vfs::export::get_name(&root, child.ino()), None);
    // `.`/`..` must never be returned as a child's name.
    assert_ne!(vfs::export::get_name(&parent, parent.ino()).as_deref(), Some("."));
    let _ = sb;
}

/// The full connectable decode: parent identity → parent inode → child's name →
/// a `(parent, name)` dentry. The reopened file has a renderable path, which is
/// the entire point of `AT_HANDLE_CONNECTABLE`; a disconnected alias would not.
#[test]
fn connectable_handle_reconnects_child_under_its_parent() {
    let (m, sb) = mount();
    let st = m.state();
    st.mkdir_at(b"/conn", 0o755).expect("mkdir");
    let child = st.create_at(b"/conn/file.bin", 0o644).expect("create");
    let parent = st.lookup_inode_any(b"/conn").expect("parent");
    let (child_h, parent_h) = (handle_of(&child), handle_of(&parent));

    // Decode side, exactly as slot 304 sequences it.
    let decoded_parent = sb.s_op.fh_to_parent(&sb, parent_h.0, parent_h.1).expect("parent decodes");
    let decoded_child = sb.s_op.fh_to_dentry(&sb, child_h.0, child_h.1).expect("child decodes");
    let name = vfs::export::get_name(&decoded_parent, decoded_child.ino()).expect("name found");
    assert_eq!(name, "file.bin");

    let pd = vfs::export::fh_alias(decoded_parent);
    let cd = vfs::export::reconnect_child(&pd, &name, &decoded_child).expect("reconnects");
    assert_eq!(cd.name(), "file.bin", "the reconnected dentry carries the real name");
    let cd_parent = cd.parent().expect("reconnected dentry has a parent");
    assert!(Arc::ptr_eq(cd_parent, &pd), "…and it is the parent the handle named");
    assert_eq!(cd.inode().expect("positive").ino(), child.ino());
}

/// A connectable handle whose child was moved out of the named parent no longer
/// reconnects: the name scan finds nothing, which is ESTALE at the syscall
/// rather than a silent downgrade to a pathless alias.
#[test]
fn connectable_decode_fails_when_the_child_left_the_parent() {
    let (m, sb) = mount();
    let st = m.state();
    st.mkdir_at(b"/from", 0o755).expect("mkdir from");
    st.mkdir_at(b"/to", 0o755).expect("mkdir to");
    let child = st.create_at(b"/from/moved.bin", 0o644).expect("create");
    let parent = st.lookup_inode_any(b"/from").expect("parent");
    let (child_h, parent_h) = (handle_of(&child), handle_of(&parent));

    st.rename_at(b"/from/moved.bin", b"/to/moved.bin").expect("rename away");

    let decoded_parent = sb.s_op.fh_to_parent(&sb, parent_h.0, parent_h.1).expect("parent decodes");
    let decoded_child = sb.s_op.fh_to_dentry(&sb, child_h.0, child_h.1).expect("child still exists");
    assert_eq!(vfs::export::get_name(&decoded_parent, decoded_child.ino()), None,
        "the child is no longer an entry of the parent the handle named");
}
