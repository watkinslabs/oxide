//! The namespace operations driven through the INTERFACE, not the volume.
//!
//! The volume suite proves what the medium ends up holding. These prove the
//! request survives the layer above it: a backend that reduced
//! `RENAME_EXCHANGE` to a plain move, or answered `O_TMPFILE` with "not
//! supported", would pass every volume test in the tree — the flags and the
//! entry point are what the interface hands down, and nothing below this file
//! can check that they arrived.

use alloc::sync::Arc;
use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;

use vfs::namei::{RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT};
use vfs::superblock::SuperOps;
use vfs::{CreateCtx, FileType, InodeRef, VfsError};

use crate::mount::sb::F2fsSuperOps;
use crate::mount::F2fs;
use crate::opts::Options;
use crate::test_image;
use crate::uapi::BLKSIZE;

const BS: u32 = BLKSIZE as u32;

fn mounted() -> Arc<F2fs> {
    let bytes = test_image::with_root().finish();
    let blocks = bytes.len() as u64 / u64::from(BS);
    let dev: Arc<MemDisk<TaskList>> = MemDisk::new(BS, blocks);
    let mut req = BlockRequest::new_write(0, blocks as u32, bytes);
    dev.submit_sync(&mut req).expect("device write");
    F2fs::open_with(dev, "/dev/fake", true, Options::defaults()).expect("mount")
}

fn root(fs: &Arc<F2fs>) -> InodeRef { fs.root_inode().expect("root") }

fn file(dir: &InodeRef, name: &str) -> InodeRef {
    dir.create_child(name, 0o644, &CreateCtx::root()).expect("create")
}

#[test]
fn an_exchange_reaches_the_volume_through_the_interface() {
    let fs = mounted();
    let dir = root(&fs);
    let a = file(&dir, "a");
    let b = file(&dir, "b");
    assert_ne!(a.ino(), b.ino());
    dir.rename_child("a", &dir, "b", RENAME_EXCHANGE, &CreateCtx::root()).expect("exchange");
    // Both sides: a plain move would leave `a` gone.
    assert_eq!(dir.lookup("a").expect("a").ino(), b.ino());
    assert_eq!(dir.lookup("b").expect("b").ino(), a.ino());
}

#[test]
fn a_whiteout_rename_reaches_the_volume_through_the_interface() {
    let fs = mounted();
    let dir = root(&fs);
    let a = file(&dir, "a");
    dir.rename_child("a", &dir, "b", RENAME_WHITEOUT, &CreateCtx::root()).expect("whiteout");
    assert_eq!(dir.lookup("b").expect("b").ino(), a.ino());
    let marker = dir.lookup("a").expect("marker");
    assert_eq!(marker.file_type(), FileType::CharDev);
    assert_ne!(marker.ino(), a.ino());
}

#[test]
fn a_flag_the_backend_cannot_answer_for_is_refused_through_the_interface() {
    let fs = mounted();
    let dir = root(&fs);
    file(&dir, "a");
    assert_eq!(dir.rename_child("a", &dir, "b", 1 << 3, &CreateCtx::root()),
               Err(VfsError::Einval));
    assert!(dir.lookup("a").is_ok());
}

#[test]
fn refusing_to_replace_still_works_through_the_interface() {
    let fs = mounted();
    let dir = root(&fs);
    file(&dir, "a");
    file(&dir, "b");
    assert_eq!(dir.rename_child("a", &dir, "b", RENAME_NOREPLACE, &CreateCtx::root()),
               Err(VfsError::Eexist));
}

#[test]
fn a_temporary_file_is_made_through_the_interface_with_no_links() {
    let fs = mounted();
    let dir = root(&fs);
    let tmp = dir.tmpfile(0o600, &CreateCtx::root()).expect("tmpfile");
    assert_eq!(tmp.nlink(), 0);
    assert_eq!(tmp.file_type(), FileType::Regular);
    // Unreachable by name, which is the whole request.
    assert!(dir.lookup("").is_err());
    let v = fs.volume.lock();
    assert!(v.is_orphan(tmp.ino() as u32));
}

#[test]
fn naming_a_temporary_file_through_the_interface_gives_it_its_link() {
    let fs = mounted();
    let dir = root(&fs);
    let tmp = dir.tmpfile(0o600, &CreateCtx::root()).expect("tmpfile");
    dir.link_child(&tmp, "now-named", &CreateCtx::root()).expect("link");
    assert_eq!(tmp.nlink(), 1);
    assert_eq!(dir.lookup("now-named").expect("named").ino(), tmp.ino());
    let v = fs.volume.lock();
    assert!(!v.is_orphan(tmp.ino() as u32));
}

#[test]
fn a_moved_directory_moves_its_cached_parent_counts_too() {
    let fs = mounted();
    let dir = root(&fs);
    let x = dir.mkdir("x", 0o755, &CreateCtx::root()).expect("x");
    let y = dir.mkdir("y", 0o755, &CreateCtx::root()).expect("y");
    x.mkdir("m", 0o755, &CreateCtx::root()).expect("m");
    let (lx, ly) = (x.nlink(), y.nlink());
    x.rename_child("m", &y, "m", 0, &CreateCtx::root()).expect("rename");
    assert_eq!(x.nlink(), lx - 1);
    assert_eq!(y.nlink(), ly + 1);
}

#[test]
fn evicting_an_unnamed_file_frees_it_rather_than_leaving_it_for_the_next_mount() {
    let fs = mounted();
    let dir = root(&fs);
    let tmp = dir.tmpfile(0o600, &CreateCtx::root()).expect("tmpfile");
    let ino = tmp.ino() as u32;
    assert!(fs.volume.lock().is_orphan(ino));
    // The terminal reference drop, which is what the interface calls when the
    // last handle on a link-less inode goes.
    let sops = F2fsSuperOps { fs: Arc::clone(&fs) };
    sops.evict_inode(&tmp);
    let v = fs.volume.lock();
    assert!(!v.is_orphan(ino), "the inode is still parked after eviction");
    assert!(v.read_inode(ino).is_err(), "the inode was not freed");
}

#[test]
fn evicting_a_file_that_gained_a_name_leaves_it_alone() {
    let fs = mounted();
    let dir = root(&fs);
    let tmp = dir.tmpfile(0o600, &CreateCtx::root()).expect("tmpfile");
    let ino = tmp.ino() as u32;
    dir.link_child(&tmp, "kept", &CreateCtx::root()).expect("link");
    let sops = F2fsSuperOps { fs: Arc::clone(&fs) };
    sops.evict_inode(&tmp);
    let v = fs.volume.lock();
    assert!(v.read_inode(ino).is_ok(), "a named file was freed at eviction");
    // And the hold is gone, so a later unlink is not told something holds it.
    assert!(!v.inode_is_open(ino));
}
