//! The two parent-directory reasons, driven against a live volume.
//!
//! Both are EVENTS the mount recorded rather than states the medium shows, so
//! the thing under test is the whole path: the operation records, the
//! checkpoint retires, and `fsync` reads the list. A test that only called the
//! decision function would pass with nothing recording anything.

use crate::mode::{S_IFDIR, S_IFREG};
use crate::opts::{FsyncMode, Options};
use crate::test_image::{self, ROOT_INO};
use crate::volume::fsync::CpReason;
use crate::volume::{NewInode, Volume};
use sectors::MemImage;

const NOW: (u64, u32) = (1_800_000_000, 11);

fn spec(mode: u16) -> NewInode { NewInode { mode, uid: 0, gid: 0, rdev: 0, now: NOW } }

fn strict() -> Options { Options { fsync_mode: FsyncMode::Strict, ..Options::defaults() } }

/// A checkpointed directory holding one checkpointed file, which is the state
/// in which the chain is otherwise available.
fn dir_with_file(opts: Options) -> (Volume<MemImage>, u32, u32) {
    let mut v = test_image::with_root().mount_opts(opts).expect("mount");
    let dir = v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).expect("mkdir");
    let ino = v.create(dir, b"f", &spec(S_IFREG | 0o644), None).expect("create");
    v.write_file(ino, 0, b"body").expect("write");
    v.commit().expect("commit");
    (v, dir, ino)
}

/// Make the file worth syncing again without touching its parent.
fn dirty_file(v: &mut Volume<MemImage>, ino: u32) {
    v.write_file(ino, 0, b"more").expect("write");
}

// ------------------------------------------------------- a rewritten parent

#[test]
fn a_parents_rewritten_attributes_take_the_checkpoint() {
    let (mut v, dir, ino) = dir_with_file(Options::defaults());
    v.set_xattr(dir, "user.k", Some(b"v"), false, false).expect("setxattr");
    dirty_file(&mut v, ino);
    assert_eq!(v.fsync(ino).expect("fsync"), CpReason::XattrDir);
}

#[test]
fn attributes_written_on_the_file_itself_do_not() {
    // The file's own attributes travel in its own inode block, which the
    // chain already carries. Recording those would make every setfattr on a
    // file cost a checkpoint.
    let (mut v, _, ino) = dir_with_file(Options::defaults());
    v.set_xattr(ino, "user.k", Some(b"v"), false, false).expect("setxattr");
    dirty_file(&mut v, ino);
    assert_eq!(v.fsync(ino).expect("fsync"), CpReason::None);
}

#[test]
fn attributes_on_an_unrelated_directory_do_not() {
    let (mut v, _, ino) = dir_with_file(Options::defaults());
    let other = v.create(ROOT_INO, b"o", &spec(S_IFDIR | 0o755), None).expect("mkdir");
    v.set_xattr(other, "user.k", Some(b"v"), false, false).expect("setxattr");
    dirty_file(&mut v, ino);
    assert_eq!(v.fsync(ino).expect("fsync"), CpReason::None);
}

#[test]
fn a_checkpoint_retires_the_rewritten_parent() {
    let (mut v, dir, ino) = dir_with_file(Options::defaults());
    v.set_xattr(dir, "user.k", Some(b"v"), false, false).expect("setxattr");
    v.commit().expect("commit");
    dirty_file(&mut v, ino);
    assert_eq!(v.fsync(ino).expect("fsync"), CpReason::None);
}

#[test]
fn a_strict_mount_answers_a_rewritten_directory_volume_wide() {
    // Strict promises a consistent TREE, so it owes a checkpoint for any file
    // at all rather than only for children of the directory that changed.
    let (mut v, dir, ino) = dir_with_file(strict());
    let elsewhere = v.create(ROOT_INO, b"e", &spec(S_IFREG | 0o644), None).expect("create");
    v.write_file(elsewhere, 0, b"x").expect("write");
    v.set_xattr(dir, "user.k", Some(b"v"), false, false).expect("setxattr");
    dirty_file(&mut v, ino);
    assert_eq!(v.fsync(elsewhere).expect("elsewhere"), CpReason::SbNeedCp);
    // That first fsync wrote the checkpoint, which is what retires the debt.
    dirty_file(&mut v, ino);
    assert_eq!(v.fsync(ino).expect("child"), CpReason::None);
}

// ------------------------------------------------------------- moved names

#[test]
fn a_rename_records_the_destination_under_a_strict_mount() {
    let (mut v, dir, ino) = dir_with_file(strict());
    let spare = v.create(ROOT_INO, b"s", &spec(S_IFREG | 0o644), None).expect("create");
    v.commit().expect("commit");
    let _ = spare;
    v.rename(ROOT_INO, b"s", dir, b"s", false, NOW).expect("rename");
    dirty_file(&mut v, ino);
    // The file's own name is already checkpointed, so the dentry mark is not
    // owed and the destination's place on the list is what remains.
    assert!(!v.need_dentry_mark(ino).expect("mark"));
    assert_eq!(v.fsync(ino).expect("fsync"), CpReason::None);
    // A file whose name IS still owed pays for it.
    let fresh = v.create(dir, b"n", &spec(S_IFREG | 0o644), None).expect("create");
    v.write_file(fresh, 0, b"y").expect("write");
    assert_eq!(v.fsync(fresh).expect("fresh"), CpReason::RecoverDir);
}

#[test]
fn a_rename_under_a_lax_mount_records_nothing() {
    let (mut v, dir, _) = dir_with_file(Options::defaults());
    v.create(ROOT_INO, b"s", &spec(S_IFREG | 0o644), None).expect("create");
    v.rename(ROOT_INO, b"s", dir, b"s", false, NOW).expect("rename");
    let fresh = v.create(dir, b"n", &spec(S_IFREG | 0o644), None).expect("create");
    v.write_file(fresh, 0, b"y").expect("write");
    assert_eq!(v.fsync(fresh).expect("fresh"), CpReason::None);
}
