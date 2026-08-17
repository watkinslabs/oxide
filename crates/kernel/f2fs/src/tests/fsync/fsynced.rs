//! Which chain writes carry the dentry mark.
//!
//! Two states have to be told apart and both are read off the medium: a file
//! the last checkpoint already holds, and a file whose name an earlier block
//! of this generation's chain already states. Marking either would be work
//! replay does not need — and, under a strict mount, a whole checkpoint.

use super::*;

use crate::mode::S_IFREG;
use crate::opts::{FsyncMode, Options};
use crate::test_image::{self, ROOT_INO};
use crate::volume::fsync::CpReason;
use crate::volume::{NewInode, Volume};
use alloc::vec;
use sectors::MemImage;

const NOW: (u64, u32) = (1_800_000_000, 7);

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

/// A volume whose root is checkpointed and whose file is not: the state in
/// which the mark is owed.
fn fresh_file(opts: Options) -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_opts(opts).expect("mount");
    let ino = v.create(ROOT_INO, b"n", &spec(), None).expect("create");
    v.write_file(ino, 0, &vec![0x5A; 2 * BLKSIZE]).expect("write");
    (v, ino)
}

#[test]
fn a_file_the_checkpoint_holds_is_owed_no_mark() {
    let (mut v, ino) = fresh_file(Options::defaults());
    v.commit().expect("commit");
    assert!(!v.need_dentry_mark(ino).expect("mark"));
}

#[test]
fn a_file_the_checkpoint_never_saw_is_owed_the_mark() {
    let (v, ino) = fresh_file(Options::defaults());
    assert!(v.need_dentry_mark(ino).expect("mark"));
    assert!(!v.inode_is_fsynced(ino).expect("fsynced"), "nothing has promised it yet");
}

#[test]
fn one_fsync_settles_the_name_and_the_next_owes_nothing() {
    let (mut v, ino) = fresh_file(Options::defaults());
    v.fsync(ino).expect("fsync");
    assert!(v.inode_is_fsynced(ino).expect("fsynced"));
    assert!(!v.need_dentry_mark(ino).expect("mark"),
            "the chain already states the name");
}

#[test]
fn only_the_first_chain_write_of_a_new_file_carries_the_mark() {
    let (mut v, ino) = fresh_file(Options::defaults());
    let first = v.fsync_chain_start();
    v.fsync(ino).expect("first");
    v.write_file(ino, 0, b"more").expect("write");
    let second = v.fsync_chain_start();
    v.fsync(ino).expect("second");
    let mark = |addr: u32| {
        let block = v.read_block(addr).expect("block");
        crate::node::footer::parse(&block).expect("footer").is_dent()
    };
    assert!(mark(first), "the first block states the file's identity");
    assert!(!mark(second), "the second must not repeat it");
}

#[test]
fn a_checkpoint_owes_the_mark_again() {
    // The chain is retired by the checkpoint, so a file created after it has
    // nothing standing for its name once more.
    let (mut v, ino) = fresh_file(Options::defaults());
    v.fsync(ino).expect("fsync");
    v.commit().expect("commit");
    assert!(!v.need_dentry_mark(ino).expect("mark"), "now the checkpoint holds it");
    let other = v.create(ROOT_INO, b"o", &spec(), None).expect("create");
    assert!(v.need_dentry_mark(other).expect("mark"));
}

#[test]
fn a_strict_mount_stops_forcing_a_checkpoint_once_the_name_is_stated() {
    // `CpReason::RecoverDir` needs BOTH halves: the parent must have lost an
    // entry under a strict mount, and this file's own name must still be owed
    // to the chain. Once an fsync has stated the name, the file's next sync is
    // an ordinary chain write even though the parent is still on the list.
    let opts = Options { fsync_mode: FsyncMode::Strict, ..Options::defaults() };
    let (mut v, ino) = fresh_file(opts);
    let gone = v.create(ROOT_INO, b"g", &spec(), None).expect("create");
    v.remove(ROOT_INO, b"g", false, NOW).expect("remove");
    let _ = gone;
    assert_eq!(v.fsync(ino).expect("first"), CpReason::RecoverDir);
    v.write_file(ino, 0, b"more").expect("write");
    assert_eq!(v.fsync(ino).expect("second"), CpReason::None);
}

#[test]
fn a_strict_mount_that_removed_nothing_takes_the_chain() {
    // The state the old approximation got wrong. Creating a file WRITES the
    // parent's node, so a rule reading "was the parent written since the
    // checkpoint" answered yes here and made every strict fsync of a new file
    // pay for a whole checkpoint. Nothing was removed, so nothing is owed.
    let opts = Options { fsync_mode: FsyncMode::Strict, ..Options::defaults() };
    let (mut v, ino) = fresh_file(opts);
    assert!(v.need_dentry_mark(ino).expect("mark"), "the name is still owed");
    assert_eq!(v.fsync(ino).expect("fsync"), CpReason::None);
}

#[test]
fn a_checkpoint_retires_the_parents_place_on_the_list() {
    let opts = Options { fsync_mode: FsyncMode::Strict, ..Options::defaults() };
    let (mut v, _) = fresh_file(opts);
    v.create(ROOT_INO, b"g", &spec(), None).expect("create");
    v.remove(ROOT_INO, b"g", false, NOW).expect("remove");
    v.commit().expect("commit");
    let after = v.create(ROOT_INO, b"a", &spec(), None).expect("create");
    v.write_file(after, 0, b"x").expect("write");
    assert_eq!(v.fsync(after).expect("fsync"), CpReason::None,
               "the checkpoint made the parent durable, so the removal is paid for");
}

#[test]
fn a_removal_under_a_lax_mount_is_not_recorded_at_all() {
    // The list is a strict-mount promise. A posix mount owes only the file it
    // is syncing, so a sibling's removal is none of its business.
    let (mut v, ino) = fresh_file(Options::defaults());
    v.create(ROOT_INO, b"g", &spec(), None).expect("create");
    v.remove(ROOT_INO, b"g", false, NOW).expect("remove");
    assert_eq!(v.fsync(ino).expect("fsync"), CpReason::None);
}

#[test]
fn the_walk_starts_where_the_checkpoint_left_the_log() {
    // Read off the OPEN log instead, the walk would start past everything
    // written since and conclude that nothing ever was.
    let (mut v, ino) = fresh_file(Options::defaults());
    let head = v.generation_chain_start();
    v.fsync(ino).expect("fsync");
    assert_eq!(head, v.generation_chain_start(), "the checkpoint has not moved");
    assert_ne!(head, v.fsync_chain_start(), "the log has");
}
