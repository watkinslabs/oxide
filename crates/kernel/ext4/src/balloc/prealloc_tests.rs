use super::{inode_pa_blocks, InodePrealloc};
use alloc::vec;

#[test]
fn inode_pa_can_serve_an_interior_logical_block() {
    let pa = InodePrealloc { logical_start: 100, blocks: vec![40, 41, 42, 43], used: vec![false; 4] };
    assert_eq!(inode_pa_blocks(&pa, 102, 2), Some(vec![42, 43]));
}

#[test]
fn inode_pa_stops_at_a_consumed_block() {
    let pa = InodePrealloc { logical_start: 100, blocks: vec![40, 41, 42], used: vec![false, true, false] };
    assert_eq!(inode_pa_blocks(&pa, 100, 3), Some(vec![40]));
    assert_eq!(inode_pa_blocks(&pa, 101, 1), None);
    assert_eq!(inode_pa_blocks(&pa, 102, 1), Some(vec![42]));
}
