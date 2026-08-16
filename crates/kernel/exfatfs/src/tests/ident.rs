use super::*;
use crate::uapi::{DENTRY_BYTES, ROOT_INO};

#[test]
fn an_offset_and_an_index_are_the_same_thing_in_two_units() {
    assert_eq!(index_of_offset(0), 0);
    assert_eq!(index_of_offset(DENTRY_BYTES as u64), 1);
    assert_eq!(index_of_offset(DENTRY_BYTES as u64 * 7), 7);
    assert_eq!(offset_of_index(7), DENTRY_BYTES as u64 * 7);
}

#[test]
fn the_two_halves_cannot_reach_into_each_other() {
    let a = inode_number(&Position { dir_cluster: 2, entry_index: 0 });
    let b = inode_number(&Position { dir_cluster: 1, entry_index: u32::MAX });
    assert_ne!(a, b);
    assert_eq!(a >> 32, 2);
    assert_eq!(a & 0xFFFF_FFFF, 0);
}

#[test]
fn two_sets_in_one_directory_get_two_numbers() {
    let a = inode_number(&Position { dir_cluster: 5, entry_index: 0 });
    let b = inode_number(&Position { dir_cluster: 5, entry_index: 3 });
    assert_ne!(a, b);
}

#[test]
fn one_set_keeps_its_number_across_lookups() {
    let pos = Position { dir_cluster: 9, entry_index: 4 };
    assert_eq!(inode_number(&pos), inode_number(&pos));
}

#[test]
fn two_empty_files_do_not_share_a_number() {
    // Which is what deriving identity from the first cluster would do: an
    // empty file has none.
    let a = inode_number(&Position { dir_cluster: 2, entry_index: 3 });
    let b = inode_number(&Position { dir_cluster: 2, entry_index: 6 });
    assert_ne!(a, b);
}

#[test]
fn no_entry_set_can_collide_with_the_root() {
    // Every directory's cluster is at least two, so the high half of any
    // derived number is at least two — the root's number is one.
    assert_eq!(root_inode_number(), ROOT_INO);
    let lowest = inode_number(&Position { dir_cluster: 2, entry_index: 0 });
    assert!(lowest > ROOT_INO);
}
