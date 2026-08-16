//! Which indirection steps a block index takes.
//!
//! Every boundary is tested as a PAIR — the last index of one range and the
//! first of the next — because an off-by-one there does not fail: it reads a
//! block through the wrong level and returns another part of the file.

use super::*;
use crate::uapi::{DEF_ADDRS_PER_BLOCK, NIDS_PER_BLOCK, NODE_DIND_BLOCK, NODE_DIR1_BLOCK,
                  NODE_DIR2_BLOCK, NODE_IND1_BLOCK, NODE_IND2_BLOCK};

/// A typical inode width: the nominal array less the extra attributes and the
/// inline attribute reservation.
const APB: usize = 864;
const DIRECT: u64 = DEF_ADDRS_PER_BLOCK as u64;
const DPTRS: u64 = NIDS_PER_BLOCK as u64;

/// Where each range begins, in file block indices.
const D1: u64 = APB as u64;
const D2: u64 = D1 + DIRECT;
const I1: u64 = D2 + DIRECT;
const I2: u64 = I1 + DIRECT * DPTRS;
const DIND: u64 = I2 + DIRECT * DPTRS;
const END: u64 = DIND + DIRECT * DPTRS * DPTRS;

fn step(block: u64) -> Step { node_path(APB, block).unwrap().step() }

#[test]
fn the_derived_widths_are_what_the_format_defines() {
    assert_eq!(DEF_ADDRS_PER_BLOCK, 1018);
    assert_eq!(NIDS_PER_BLOCK, 1018);
    assert_eq!(NODE_DIR1_BLOCK, 924);
    assert_eq!(NODE_DIR2_BLOCK, 925);
    assert_eq!(NODE_IND1_BLOCK, 926);
    assert_eq!(NODE_IND2_BLOCK, 927);
    assert_eq!(NODE_DIND_BLOCK, 928);
}

#[test]
fn block_zero_is_the_inodes_own_first_slot() {
    assert_eq!(step(0), Step::InInode { index: 0 });
    assert_eq!(node_path(APB, 0).unwrap().level, 0);
}

#[test]
fn the_last_index_inside_the_inode_is_the_width_less_one() {
    assert_eq!(step(D1 - 1), Step::InInode { index: APB - 1 });
}

#[test]
fn the_first_index_past_the_inode_is_the_first_direct_nodes_first_slot() {
    // The boundary is an exact equality: this index is slot ZERO of the first
    // direct node, not the last slot of the inode.
    assert_eq!(step(D1), Step::Direct { nid_slot: 0, index: 0 });
}

#[test]
fn the_first_direct_node_runs_a_whole_block_of_addresses() {
    assert_eq!(step(D2 - 1), Step::Direct { nid_slot: 0, index: DEF_ADDRS_PER_BLOCK - 1 });
}

#[test]
fn the_second_direct_node_begins_where_the_first_ends() {
    assert_eq!(step(D2), Step::Direct { nid_slot: 1, index: 0 });
    assert_eq!(step(I1 - 1), Step::Direct { nid_slot: 1, index: DEF_ADDRS_PER_BLOCK - 1 });
}

#[test]
fn the_first_indirect_node_begins_where_the_second_direct_ends() {
    assert_eq!(step(I1), Step::Indirect { nid_slot: 2, dnode: 0, index: 0 });
}

#[test]
fn an_indirect_nodes_second_direct_child_starts_a_block_in() {
    assert_eq!(step(I1 + DIRECT), Step::Indirect { nid_slot: 2, dnode: 1, index: 0 });
    assert_eq!(step(I1 + DIRECT - 1),
               Step::Indirect { nid_slot: 2, dnode: 0, index: DEF_ADDRS_PER_BLOCK - 1 });
}

#[test]
fn the_first_indirect_nodes_last_index_is_its_last_childs_last_slot() {
    assert_eq!(
        step(I2 - 1),
        Step::Indirect { nid_slot: 2, dnode: NIDS_PER_BLOCK - 1, index: DEF_ADDRS_PER_BLOCK - 1 }
    );
}

#[test]
fn the_second_indirect_node_begins_where_the_first_ends() {
    assert_eq!(step(I2), Step::Indirect { nid_slot: 3, dnode: 0, index: 0 });
    assert_eq!(
        step(DIND - 1),
        Step::Indirect { nid_slot: 3, dnode: NIDS_PER_BLOCK - 1, index: DEF_ADDRS_PER_BLOCK - 1 }
    );
}

#[test]
fn the_double_indirect_node_begins_where_the_second_indirect_ends() {
    assert_eq!(step(DIND), Step::DoubleIndirect { nid_slot: 4, indirect: 0, dnode: 0, index: 0 });
}

#[test]
fn the_double_indirects_second_middle_child_starts_an_indirect_span_in() {
    assert_eq!(
        step(DIND + DIRECT * DPTRS),
        Step::DoubleIndirect { nid_slot: 4, indirect: 1, dnode: 0, index: 0 }
    );
}

#[test]
fn the_double_indirects_second_leaf_starts_a_direct_span_in() {
    assert_eq!(
        step(DIND + DIRECT),
        Step::DoubleIndirect { nid_slot: 4, indirect: 0, dnode: 1, index: 0 }
    );
}

#[test]
fn the_last_addressable_index_is_the_double_indirects_last_slot() {
    assert_eq!(
        step(END - 1),
        Step::DoubleIndirect {
            nid_slot: 4,
            indirect: NIDS_PER_BLOCK - 1,
            dnode: NIDS_PER_BLOCK - 1,
            index: DEF_ADDRS_PER_BLOCK - 1,
        }
    );
}

#[test]
fn one_index_past_the_last_is_not_addressable() {
    assert_eq!(node_path(APB, END), None);
    assert_eq!(max_block(APB), END);
}

#[test]
fn the_levels_are_zero_through_three() {
    assert_eq!(node_path(APB, 0).unwrap().level, 0);
    assert_eq!(node_path(APB, D1).unwrap().level, 1);
    assert_eq!(node_path(APB, D2).unwrap().level, 1);
    assert_eq!(node_path(APB, I1).unwrap().level, 2);
    assert_eq!(node_path(APB, I2).unwrap().level, 2);
    assert_eq!(node_path(APB, DIND).unwrap().level, 3);
}

#[test]
fn the_five_node_slots_are_named_in_order() {
    assert_eq!(node_path(APB, D1).unwrap().offset[0], NODE_DIR1_BLOCK);
    assert_eq!(node_path(APB, D2).unwrap().offset[0], NODE_DIR2_BLOCK);
    assert_eq!(node_path(APB, I1).unwrap().offset[0], NODE_IND1_BLOCK);
    assert_eq!(node_path(APB, I2).unwrap().offset[0], NODE_IND2_BLOCK);
    assert_eq!(node_path(APB, DIND).unwrap().offset[0], NODE_DIND_BLOCK);
}

#[test]
fn the_node_numbers_within_the_tree_are_what_a_footer_records() {
    assert_eq!(node_path(APB, D1).unwrap().noffset[1], 1);
    assert_eq!(node_path(APB, D2).unwrap().noffset[1], 2);
    assert_eq!(node_path(APB, I1).unwrap().noffset[1], 3);
    assert_eq!(node_path(APB, I1).unwrap().noffset[2], 4);
    assert_eq!(node_path(APB, I2).unwrap().noffset[1], 4 + NIDS_PER_BLOCK);
    assert_eq!(node_path(APB, DIND).unwrap().noffset[1], 5 + NIDS_PER_BLOCK * 2);
}

#[test]
fn a_double_indirect_node_number_accounts_for_the_middle_nodes_own_slot() {
    // Each middle node costs its own block plus a block of leaves, which is
    // what the `dptrs + 1` stride carries.
    let p = node_path(APB, DIND + DIRECT * DPTRS).unwrap();
    assert_eq!(p.noffset[2], 5 + NIDS_PER_BLOCK * 2 + 1 + (NIDS_PER_BLOCK + 1));
}

#[test]
fn a_narrower_inode_moves_every_later_boundary_down() {
    // The inode's own width is where the first boundary is; an inode with more
    // extra attributes has a smaller one, and every range shifts with it.
    let narrow = APB - 9;
    assert_eq!(node_path(narrow, narrow as u64).unwrap().step(),
               Step::Direct { nid_slot: 0, index: 0 });
    assert_eq!(node_path(narrow, narrow as u64 - 1).unwrap().step(),
               Step::InInode { index: narrow - 1 });
    // The same index lands in different places for the two widths.
    assert_ne!(node_path(narrow, narrow as u64).unwrap().step(),
               node_path(APB, narrow as u64).unwrap().step());
}

#[test]
fn max_block_moves_with_the_inode_width() {
    assert_eq!(max_block(APB) - max_block(APB - 1), 1);
}

#[test]
fn every_index_in_the_first_two_ranges_round_trips_to_a_distinct_place() {
    // A duplicate would mean two file blocks share one address slot.
    let mut seen = alloc::vec::Vec::new();
    for i in (D1 - 4)..(D1 + 4) { seen.push(step(i)); }
    for i in (D2 - 4)..(D2 + 4) { seen.push(step(i)); }
    let n = seen.len();
    seen.dedup();
    assert_eq!(seen.len(), n);
}
