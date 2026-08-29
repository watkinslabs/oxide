use super::{consume_group_prealloc_block, group_prealloc_order, inode_pa_blocks, select_group_pa, trim_group_preallocations,
            GroupPrealloc, InodePrealloc};
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

#[test]
fn locality_pa_list_grows_to_eight_then_trims_to_five_largest() {
    let mut entries = (1..=8).map(|blocks| GroupPrealloc {
        blocks: vec![0; blocks],
    }).collect();
    trim_group_preallocations(&mut entries);
    assert_eq!(entries.len(), 8);

    let mut entries = (1..=9).map(|blocks| GroupPrealloc {
        blocks: vec![0; blocks],
    }).collect();
    trim_group_preallocations(&mut entries);
    assert_eq!(entries.len(), 5);
    assert!(!entries.iter().any(|pa| pa.blocks.len() <= 4));
    assert!(entries.iter().any(|pa| pa.blocks.len() == 9));
}

#[test]
fn locality_pa_order_matches_linux_fls_buckets() {
    assert_eq!(group_prealloc_order(0), 0);
    assert_eq!(group_prealloc_order(1), 0);
    assert_eq!(group_prealloc_order(2), 1);
    assert_eq!(group_prealloc_order(3), 1);
    assert_eq!(group_prealloc_order(4), 2);
    assert_eq!(group_prealloc_order(1023), 9);
    assert_eq!(group_prealloc_order(u32::MAX), 9);
}

#[test]
fn locality_pa_selection_uses_the_closest_physical_goal() {
    let entries = [
        GroupPrealloc { blocks: vec![100, 101, 102] },
        GroupPrealloc { blocks: vec![180, 181, 182] },
        GroupPrealloc { blocks: vec![140] },
    ];
    assert_eq!(select_group_pa(&entries, 2, 171).unwrap().blocks[0], 180);
    assert!(select_group_pa(&entries, 4, 171).is_none());
}

#[test]
fn locality_pa_consumption_preserves_contiguous_remaining_segments() {
    let mut entries = vec![
        GroupPrealloc { blocks: vec![100, 101, 102] },
        GroupPrealloc { blocks: vec![200, 201, 202] },
    ];
    assert!(consume_group_prealloc_block(&mut entries, 201));
    assert_eq!(entries[0].blocks, vec![100, 101, 102]);
    assert_eq!(entries[1].blocks, vec![200]);
    assert_eq!(entries[2].blocks, vec![202]);
    assert!(!consume_group_prealloc_block(&mut entries, 999));
}
