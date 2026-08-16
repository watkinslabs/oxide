//! The destination a move names, decided over stated facts.
//!
//! The decision is separated from the descriptor lookup for the same reason
//! every other decision in this surface is: the lookup needs a task, a
//! descriptor table and two open descriptions, and the RULE needs none of
//! them. Only the rule can be wrong in a way that matters — which of the three
//! answers a caller gets decides which errno it is told, and the two failing
//! answers are refused at different rungs.

use crate::ioctl::vfs::{dst_of, DstFacts};
use crate::ioctl::DstFd;

fn ours() -> DstFacts {
    DstFacts { writable: true, same_mount: true, same_volume: true, ino: 7 }
}

#[test]
fn a_descriptor_of_the_same_volume_is_the_file_it_names() {
    assert_eq!(dst_of(Some(ours())), DstFd::Ours(7));
}

#[test]
fn no_descriptor_at_all_is_the_same_answer_as_one_that_cannot_be_written() {
    // Both are refused at the same rung and with the same errno: neither is a
    // destination. Reporting one of them as "elsewhere" would tell a caller
    // its descriptor was fine and the filesystem was wrong.
    assert_eq!(dst_of(None), DstFd::Unusable);
    assert_eq!(dst_of(Some(DstFacts { writable: false, ..ours() })), DstFd::Unusable);
}

#[test]
fn a_descriptor_that_cannot_be_written_is_unusable_even_on_another_volume() {
    // The rungs are ordered: being unwritable is decided first, so a
    // descriptor that is both unwritable and foreign reports the descriptor.
    let bad = DstFacts { writable: false, same_mount: false, same_volume: false, ..ours() };
    assert_eq!(dst_of(Some(bad)), DstFd::Unusable);
}

#[test]
fn another_mount_of_the_same_volume_is_still_another_mount() {
    // Both halves of the test are made. A move between two mounts of one
    // volume is not this operation, and answering `Ours` would carry out a
    // move the interface does not define.
    let other = DstFacts { same_mount: false, ..ours() };
    assert_eq!(dst_of(Some(other)), DstFd::Foreign);
}

#[test]
fn a_file_of_another_volume_on_the_same_mount_is_foreign() {
    let other = DstFacts { same_volume: false, ..ours() };
    assert_eq!(dst_of(Some(other)), DstFd::Foreign);
}

#[test]
fn the_inode_number_is_carried_through_untouched() {
    // The exec stage moves blocks between two inode NUMBERS; one carried
    // through wrong moves another file's blocks.
    for ino in [1u32, 3, 4096, u32::MAX] {
        assert_eq!(dst_of(Some(DstFacts { ino, ..ours() })), DstFd::Ours(ino));
    }
}
