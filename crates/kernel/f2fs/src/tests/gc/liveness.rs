//! The three records a block's liveness is read from, and their agreement.

use crate::uapi::*;
use crate::volume::curseg::{Curseg, Summary};
use crate::volume::gc::live::{alive, entry, holds_addresses, holds_nodes, owned, XATTR_NODE_OFS};

const OWNER: u32 = 40;
const ADDR: u32 = 5_000;

fn sum(nid: u32, ofs: u16) -> Summary { Summary { nid, version: 0, ofs_in_node: ofs } }

/// A summary block with three entries laid down the way a sealed log leaves
/// them.
fn block() -> Curseg {
    let mut c = Curseg::empty();
    c.set_summary(0, sum(OWNER, 0));
    c.set_summary(1, sum(OWNER, 1));
    c.set_summary(511, sum(OWNER + 1, 9));
    c
}

#[test]
fn an_entry_reads_back_the_owner_the_log_recorded() {
    let c = block();
    assert_eq!(entry(&c.sum, 0), Some(sum(OWNER, 0)));
    assert_eq!(entry(&c.sum, 1), Some(sum(OWNER, 1)));
    assert_eq!(entry(&c.sum, 511), Some(sum(OWNER + 1, 9)));
}

#[test]
fn an_entry_nothing_was_written_to_names_nobody() {
    let c = block();
    assert_eq!(entry(&c.sum, 5), Some(sum(0, 0)));
    assert!(!owned(&entry(&c.sum, 5).unwrap()));
}

#[test]
fn an_entry_past_the_array_is_refused_rather_than_read_out_of_the_journal() {
    let c = block();
    assert_eq!(entry(&c.sum, ENTRIES_IN_SUM), None);
    assert_eq!(entry(&c.sum, ENTRIES_IN_SUM + 100), None);
}

#[test]
fn the_footer_says_whether_the_block_describes_nodes() {
    let mut c = block();
    c.seal(true);
    assert!(holds_nodes(&c.sum));
    c.seal(false);
    assert!(!holds_nodes(&c.sum));
}

#[test]
fn an_unsealed_block_describes_data() {
    assert!(!holds_nodes(&Curseg::empty().sum));
}

#[test]
fn a_truncated_block_describes_neither() {
    assert!(!holds_nodes(&[0u8; 16]));
}

#[test]
fn the_reserved_node_ids_are_not_owners() {
    for nid in 0..RESERVED_NODE_NUM {
        assert!(!owned(&sum(nid, 0)), "reserved id must not own a block");
    }
    assert!(owned(&sum(RESERVED_NODE_NUM, 0)));
    assert!(owned(&sum(OWNER, 0)));
}

#[test]
fn a_block_is_alive_only_when_all_three_records_agree() {
    assert!(alive(true, &sum(OWNER, 0), Some(ADDR), ADDR));
}

#[test]
fn a_block_the_table_calls_dead_is_not_alive_however_it_is_owned() {
    assert!(!alive(false, &sum(OWNER, 0), Some(ADDR), ADDR));
}

#[test]
fn a_block_the_summary_disowns_is_not_alive() {
    assert!(!alive(true, &sum(0, 0), Some(ADDR), ADDR));
    assert!(!alive(true, &sum(1, 0), Some(ADDR), ADDR));
}

#[test]
fn a_block_whose_owner_moved_on_is_not_alive() {
    assert!(!alive(true, &sum(OWNER, 0), Some(ADDR + 1), ADDR));
}

#[test]
fn a_block_whose_owner_cannot_be_read_is_not_alive() {
    assert!(!alive(true, &sum(OWNER, 0), None, ADDR));
}

#[test]
fn the_inode_and_the_nodes_it_names_hold_addresses() {
    assert!(holds_addresses(0), "the inode itself");
    assert!(holds_addresses(1));
    assert!(holds_addresses(2));
}

#[test]
fn the_nodes_that_name_other_nodes_hold_no_addresses() {
    let n = NIDS_PER_BLOCK as u32;
    assert!(!holds_addresses(3), "first indirect");
    assert!(!holds_addresses(4 + n), "second indirect");
    assert!(!holds_addresses(5 + 2 * n), "double indirect");
    assert!(!holds_addresses(6 + 2 * n), "indirect under the double");
    assert!(!holds_addresses(6 + 2 * n + (n + 1)), "the next one along");
}

#[test]
fn a_direct_node_under_an_indirect_one_holds_addresses() {
    let n = NIDS_PER_BLOCK as u32;
    assert!(holds_addresses(4), "first direct under the first indirect");
    assert!(holds_addresses(3 + n), "last direct under it");
    assert!(holds_addresses(6 + 2 * n + 1));
    assert!(holds_addresses(6 + 2 * n + n));
}

#[test]
fn an_attribute_block_is_written_with_the_nodes_that_hold_addresses() {
    assert!(holds_addresses(XATTR_NODE_OFS));
}
