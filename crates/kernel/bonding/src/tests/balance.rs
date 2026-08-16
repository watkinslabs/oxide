// Transmit and receive load balancing tables.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::alb::{next_rx_slave, ArpView, RlbTable};
use crate::limits::{RLB_HASH_TABLE_SIZE, TLB_HASH_TABLE_SIZE, TLB_NULL_INDEX};
use crate::slave::{LinkState, SlaveRole, SlaveState};
use crate::tlb::{compute_gap, least_loaded_slave, simple_hash, TlbTable};

fn up(speed: u32, load: u64) -> SlaveState {
    SlaveState { link: LinkState::Up, carrier: true, role: SlaveRole::Active,
                 speed_mbps: speed, tlb_load: load, ..SlaveState::default() }
}

fn down() -> SlaveState {
    SlaveState { link: LinkState::Down, carrier: false, ..SlaveState::default() }
}

#[test]
fn the_fold_is_an_exclusive_or_of_every_byte() {
    assert_eq!(simple_hash(&[10, 0, 0, 1]), 10 ^ 0 ^ 0 ^ 1);
    assert_eq!(simple_hash(&[]), 0);
    // Two addresses whose octets fold the same land on one entry.
    assert_eq!(simple_hash(&[1, 2, 3, 4]), simple_hash(&[4, 3, 2, 1]));
}

#[test]
fn headroom_is_link_capacity_less_the_bits_already_charged() {
    assert_eq!(compute_gap(&up(1000, 0)), 1000i64 << 20);
    assert!(compute_gap(&up(1000, 1_000_000)) < compute_gap(&up(1000, 0)));
    assert!(compute_gap(&up(10000, 0)) > compute_gap(&up(1000, 0)));
}

#[test]
fn the_least_loaded_slave_is_the_one_with_the_most_headroom() {
    let s = vec![up(1000, 900_000), up(1000, 0), up(1000, 100)];
    assert_eq!(least_loaded_slave(&s), Some(1));
}

#[test]
fn a_slave_that_cannot_transmit_is_never_least_loaded() {
    let mut s = vec![down(), up(1000, 500)];
    s[0].speed_mbps = 100_000;
    assert_eq!(least_loaded_slave(&s), Some(1));
    assert_eq!(least_loaded_slave(&[down()]), None);
}

#[test]
fn a_new_flow_is_pinned_and_a_known_flow_keeps_its_slave() {
    let mut t = TlbTable::default();
    let s = vec![up(1000, 0), up(10000, 0)];
    let first = t.choose_channel(7, 1500, &s).unwrap();
    // The faster link has the most headroom.
    assert_eq!(first, 1);
    // A later frame on the same flow does not re-decide, even after the
    // balance shifts.
    let s2 = vec![up(100_000, 0), up(10000, 0)];
    assert_eq!(t.choose_channel(7, 1500, &s2), Some(1));
    assert_eq!(t.entry(7).tx_bytes, 3000);
}

#[test]
fn two_flows_landing_on_one_entry_share_the_pinned_slave() {
    let mut t = TlbTable::default();
    let s = vec![up(1000, 0)];
    assert_eq!(t.choose_channel(3, 100, &s), Some(0));
    assert_eq!(t.choose_channel(3, 100, &s), Some(0));
    assert_eq!(t.entry(3).tx_bytes, 200);
}

#[test]
fn assignments_chain_onto_the_owning_slaves_list() {
    let mut t = TlbTable::default();
    let s = vec![up(1000, 0)];
    t.choose_channel(1, 10, &s);
    t.choose_channel(2, 10, &s);
    assert_eq!(t.slave_head(0), 2);
    assert_eq!(t.entry(2).next, 1);
    assert_eq!(t.entry(1).prev, 2);
    assert_eq!(t.entry(1).next, TLB_NULL_INDEX);
}

#[test]
fn a_rebalance_folds_this_windows_bytes_into_the_carried_history() {
    let mut t = TlbTable::default();
    let s = vec![up(1000, 0)];
    t.choose_channel(9, 4096, &s);
    t.rebalance();
    assert_eq!(t.entry(9).tx_bytes, 0);
    assert_eq!(t.entry(9).load_history, 4096);
    assert_eq!(t.slave_load(0), 4096);
}

#[test]
fn releasing_a_slave_drops_every_flow_pinned_to_it() {
    let mut t = TlbTable::default();
    let s = vec![up(1000, 0)];
    t.choose_channel(5, 10, &s);
    assert_eq!(t.entry(5).tx_slave, Some(0));
    t.deinitialize_slave(0);
    assert_eq!(t.entry(5).tx_slave, None);
    assert_eq!(t.slave_head(0), TLB_NULL_INDEX);
}

#[test]
fn a_flow_finds_no_slave_when_none_can_transmit() {
    let mut t = TlbTable::default();
    assert_eq!(t.choose_channel(0, 100, &[down()]), None);
    assert_eq!(t.entry(0).tx_bytes, 0);
}

#[test]
fn the_tables_are_the_sizes_the_index_fold_can_address() {
    assert_eq!(TLB_HASH_TABLE_SIZE, 256);
    assert_eq!(RLB_HASH_TABLE_SIZE, 256);
}

// -------------------------------------------------------------- receive balancing

fn arp(src: [u8; 4], dst: [u8; 4]) -> ArpView {
    ArpView { ip_src: src, ip_dst: dst, mac_src: [2, 0, 0, 0, 0, 1],
              mac_dst: [0xff; 6], vlan_id: 0 }
}

#[test]
fn the_receive_round_robin_skips_slaves_that_cannot_carry_traffic() {
    let s = vec![up(1000, 0), down(), up(1000, 0)];
    assert_eq!(next_rx_slave(&s, 0), Some(0));
    assert_eq!(next_rx_slave(&s, 1), Some(2));
    assert_eq!(next_rx_slave(&s, 2), Some(2));
    assert_eq!(next_rx_slave(&[down()], 0), None);
    assert_eq!(next_rx_slave(&[], 0), None);
}

#[test]
fn clients_are_spread_across_the_slaves_in_turn() {
    let mut t = RlbTable::default();
    let s = vec![up(1000, 0), up(1000, 0)];
    let picks: Vec<Option<usize>> = (1u8..=4)
        .map(|n| t.choose_channel(&arp([10, 0, 0, n], [10, 0, 1, n]), &s, None).slave)
        .collect();
    assert_eq!(picks, vec![Some(0), Some(1), Some(0), Some(1)]);
}

#[test]
fn a_returning_client_keeps_its_slave_and_the_reply_is_rewritten() {
    let mut t = RlbTable::default();
    let s = vec![up(1000, 0), up(1000, 0)];
    let a = arp([10, 0, 0, 1], [10, 0, 1, 1]);
    let first = t.choose_channel(&a, &s, None);
    assert!(first.rewrite_src);
    let again = t.choose_channel(&a, &s, None);
    assert_eq!(again.slave, first.slave);
    assert_eq!(again.index, first.index);
    assert!(again.rewrite_src);
}

#[test]
fn a_reply_teaches_the_client_its_real_unicast_address() {
    let mut t = RlbTable::default();
    let s = vec![up(1000, 0)];
    let mut a = arp([10, 0, 0, 1], [10, 0, 1, 1]);
    let d = t.choose_channel(&a, &s, None);
    assert_eq!(t.client(d.index).mac_dst, [0xff; 6]);
    a.mac_dst = [2, 0, 0, 0, 0, 9];
    t.choose_channel(&a, &s, None);
    assert_eq!(t.client(d.index).mac_dst, [2, 0, 0, 0, 0, 9]);
}

#[test]
fn a_refresh_is_owed_only_once_a_real_unicast_address_is_known() {
    let mut t = RlbTable::default();
    let s = vec![up(1000, 0)];
    let mut a = arp([10, 0, 0, 1], [10, 0, 1, 1]);
    let d = t.choose_channel(&a, &s, None);
    assert!(!t.client(d.index).ntt);
    a.ip_src = [10, 0, 0, 2];
    a.ip_dst = [10, 0, 1, 2];
    a.mac_dst = [2, 0, 0, 0, 0, 9];
    let d2 = t.choose_channel(&a, &s, None);
    assert!(t.client(d2.index).ntt);
    assert_eq!(t.pending_updates().count(), 1);
    t.clear_updates();
    assert_eq!(t.pending_updates().count(), 0);
}

#[test]
fn a_colliding_client_displaces_the_incumbent_onto_the_active_slave() {
    let mut t = RlbTable::default();
    let s = vec![up(1000, 0), up(1000, 0)];
    // Both destinations fold to the same entry.
    let a = arp([10, 0, 0, 1], [1, 2, 3, 4]);
    let b = arp([10, 0, 0, 2], [4, 3, 2, 1]);
    let first = t.choose_channel(&a, &s, None);
    let second = t.choose_channel(&b, &s, Some(1));
    assert_eq!(first.index, second.index);
    assert_eq!(t.client(second.index).ip_src, [10, 0, 0, 2]);
}

#[test]
fn releasing_a_slave_moves_its_clients_to_the_replacement() {
    let mut t = RlbTable::default();
    let s = vec![up(1000, 0)];
    let d = t.choose_channel(&arp([10, 0, 0, 1], [10, 0, 1, 1]), &s, None);
    assert_eq!(t.client(d.index).slave, Some(0));
    t.purge_slave(0, Some(1));
    assert_eq!(t.client(d.index).slave, Some(1));
    assert!(t.client(d.index).ntt);
}

#[test]
fn with_nothing_able_to_receive_no_client_is_assigned() {
    let mut t = RlbTable::default();
    let d = t.choose_channel(&arp([10, 0, 0, 1], [10, 0, 1, 1]), &[down()], None);
    assert_eq!(d.slave, None);
    assert!(!d.rewrite_src);
}
