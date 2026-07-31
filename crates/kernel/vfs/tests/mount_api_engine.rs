//! B1582: the three mount-engine operations the new mount API needs and that
//! the syscall shims previously either faked or dropped on the floor —
//! `open_tree(OPEN_TREE_CLONE)`'s copy admission ladder, `move_mount`'s
//! `MOVE_MOUNT_SET_GROUP`, and `move_mount`'s `MOVE_MOUNT_BENEATH` slot swap.
//! Driven against the real global mount engine through the hosted
//! dentry-identity fixture. Serializes on `SERIAL`.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::Propagation;
use vfs::{FileType, InodeRef, KResult, VfsError};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::install();
    g
}

struct TFs { root_ino: u64 }
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
    fn root(&self) -> Option<InodeRef> { Some(tdir(self.root_ino)) }
}
struct TDirOps;
impl vfs::InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Ok(tdir(0xB00)) }
}
fn tdir(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755),
        Arc::new(TDirOps), vfs::default_file_ops()).build()
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { root_ino: ino }) }

fn mnt(p: &str) -> Arc<vfs::mount::Mount> {
    common::mount_at_path_exact(p).expect("mount present")
}

fn root_of(p: &str) -> Arc<vfs::Dentry> {
    mnt(p).mnt_root().expect("mount root")
}

// ---------------------------------------------------------------------------
// __do_loopback admission (open_tree(OPEN_TREE_CLONE) / recursive bind)
// ---------------------------------------------------------------------------

#[test]
fn clone_of_an_unbindable_mount_is_einval() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/src", fs(0xA)).expect("src");
    common::set_propagation("/src", Propagation::Unbindable).expect("unbindable");
    let m = mnt("/src");
    let base = root_of("/src");
    assert_eq!(vfs::mount::may_clone_mount_tree(&m, &base, false), Err(VfsError::Einval));
    assert_eq!(vfs::mount::may_clone_mount_tree(&m, &base, true), Err(VfsError::Einval));
}

#[test]
fn clone_of_an_ordinary_mount_is_allowed_either_way() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/src", fs(0xA)).expect("src");
    let m = mnt("/src");
    let base = root_of("/src");
    assert_eq!(vfs::mount::may_clone_mount_tree(&m, &base, false), Ok(()));
    assert_eq!(vfs::mount::may_clone_mount_tree(&m, &base, true), Ok(()));
}

// ---------------------------------------------------------------------------
// MOVE_MOUNT_SET_GROUP (do_set_group)
// ---------------------------------------------------------------------------

/// Clone `/src` onto `dst` as a BIND: same superblock, same root dentry. Two
/// independent `register` calls of one `FileSystem` build DISTINCT superblocks,
/// which `do_set_group` rightly refuses.
fn bind_clone_of_src_at(dst: &str) {
    let src = mnt("/src");
    let parent = vfs::mount::root_mount_id(vfs::mount::current_ns()).expect("ns root");
    vfs::mount::register_bind_clone_under(
        parent, common::dentry(dst), src.mnt_id, root_of("/src")).expect("bind clone");
}

/// Build `/src` shared and `/dst` private over the SAME superblock, which is
/// what a `set_group` caller has after binding one onto the other.
fn shared_source_and_private_dest() -> (Arc<vfs::mount::Mount>, Arc<vfs::mount::Mount>) {
    common::register("/", fs(0x1)).expect("root");
    common::register("/src", fs(0xA)).expect("src");
    // A BIND of `/src` shares its superblock and its root dentry, which is the
    // only shape `do_set_group` accepts: two independent mounts of the same
    // filesystem have distinct superblocks and are refused.
    bind_clone_of_src_at("/dst");
    common::set_propagation("/src", Propagation::Shared).expect("shared");
    (mnt("/src"), mnt("/dst"))
}

#[test]
fn set_group_makes_the_destination_a_peer_of_a_shared_source() {
    let _g = guard();
    let (from, to) = shared_source_and_private_dest();
    assert_eq!(vfs::mount::set_group(&from, true, &to, true), Ok(()));
    assert_eq!(common::peer_group_of("/dst"), common::peer_group_of("/src"));
    assert_ne!(common::peer_group_of("/dst"), 0);
}

#[test]
fn set_group_requires_both_paths_to_be_mount_roots() {
    let _g = guard();
    let (from, to) = shared_source_and_private_dest();
    assert_eq!(vfs::mount::set_group(&from, false, &to, true), Err(VfsError::Einval));
    assert_eq!(vfs::mount::set_group(&from, true, &to, false), Err(VfsError::Einval));
}

#[test]
fn set_group_refuses_a_private_source() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    let f = fs(0xA);
    common::register("/src", f).expect("src");
    bind_clone_of_src_at("/dst");
    // Neither side shared: the source has no group to hand over.
    assert_eq!(vfs::mount::set_group(&mnt("/src"), true, &mnt("/dst"), true),
               Err(VfsError::Einval));
}

#[test]
fn set_group_refuses_a_destination_that_is_already_shared() {
    let _g = guard();
    let (from, to) = shared_source_and_private_dest();
    common::set_propagation("/dst", Propagation::Shared).expect("dst shared");
    assert_eq!(vfs::mount::set_group(&from, true, &mnt("/dst"), true), Err(VfsError::Einval));
    let _ = to;
}

#[test]
fn set_group_refuses_across_different_superblocks() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/src", fs(0xA)).expect("src");
    common::register("/dst", fs(0xB)).expect("dst");
    common::set_propagation("/src", Propagation::Shared).expect("shared");
    assert_eq!(vfs::mount::set_group(&mnt("/src"), true, &mnt("/dst"), true),
               Err(VfsError::Einval));
}

// ---------------------------------------------------------------------------
// MOVE_MOUNT_BENEATH
// ---------------------------------------------------------------------------

#[test]
fn beneath_puts_the_source_under_the_top_mount() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/mnt", fs(0xC1)).expect("top");
    common::register("/staging", fs(0xC2)).expect("src");
    let top = mnt("/mnt");
    let src = mnt("/staging");
    let top_parent = top.parent_id.load(std::sync::atomic::Ordering::Acquire);

    assert_eq!(vfs::mount::move_mount_beneath(src.mnt_id, top.mnt_id), Ok(()));

    // The source now occupies the slot the top mount held...
    assert_eq!(src.parent_id.load(std::sync::atomic::Ordering::Acquire), top_parent);
    // ...and the top mount hangs off the source's own root.
    assert_eq!(top.parent_id.load(std::sync::atomic::Ordering::Acquire), src.mnt_id);
    // The slot on the old parent now holds the source...
    assert_eq!(common::mount_at_path_exact("/mnt").map(|m| m.mnt_id), Some(src.mnt_id));
    // ...and the top mount still covers it, so the pathname never uncovered —
    // the whole point of the flag.
    let src_root = src.mnt_root().expect("source root");
    assert_eq!(vfs::mount::__lookup_mnt(src.mnt_id, &src_root).map(|m| m.mnt_id),
               Some(top.mnt_id));
}

#[test]
fn beneath_refuses_the_namespace_root_as_the_top_mount() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/staging", fs(0xC2)).expect("src");
    let root = mnt("/");
    let src = mnt("/staging");
    assert_eq!(vfs::mount::move_mount_beneath(src.mnt_id, root.mnt_id), Err(VfsError::Einval));
}

#[test]
fn beneath_refuses_to_move_a_mount_under_itself() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/mnt", fs(0xC1)).expect("top");
    let top = mnt("/mnt");
    assert_eq!(vfs::mount::move_mount_beneath(top.mnt_id, top.mnt_id), Err(VfsError::Einval));
}

#[test]
fn beneath_refuses_a_top_mount_descended_from_the_source() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/src", fs(0xA)).expect("src");
    common::register("/src/inner", fs(0xB)).expect("inner");
    // `/src/inner`'s parent IS `/src`, so sliding `/src` beneath it would make
    // the tree its own ancestor — Linux's ELOOP, not EINVAL.
    assert_eq!(vfs::mount::move_mount_beneath(mnt("/src").mnt_id, mnt("/src/inner").mnt_id),
               Err(VfsError::Eloop));
}

#[test]
fn beneath_refuses_a_locked_source() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/mnt", fs(0xC1)).expect("top");
    common::register("/staging", fs(0xC2)).expect("src");
    let src = mnt("/staging");
    src.set_internal_flag(vfs::mount::MNT_LOCKED);
    assert_eq!(vfs::mount::move_mount_beneath(src.mnt_id, mnt("/mnt").mnt_id),
               Err(VfsError::Einval));
}

#[test]
fn beneath_refuses_an_unknown_mount_id() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/mnt", fs(0xC1)).expect("top");
    let missing = u64::MAX;
    assert_eq!(vfs::mount::move_mount_beneath(missing, mnt("/mnt").mnt_id), Err(VfsError::Einval));
    assert_eq!(vfs::mount::move_mount_beneath(mnt("/mnt").mnt_id, missing), Err(VfsError::Einval));
}

/// Keeps the unused-import lint honest about `KResult` while documenting that
/// every engine entry point above returns one.
#[allow(dead_code)]
fn _kresult_shape(r: KResult<()>) -> bool { r.is_ok() }
