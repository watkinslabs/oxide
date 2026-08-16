// Per-mode transmit selection.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::hash::FlowKeys;
use crate::mode::{
    aggregator_slaves, broadcast_slaves, hash_slave, roundrobin_slave, rr_gen_slave_id,
    select_tx, slave_by_id, usable_slaves, TxContext, TxTarget,
};
use crate::slave::{LinkState, SlaveRole, SlaveState};
use crate::uapi::{
    BOND_MODE_8023AD, BOND_MODE_ACTIVEBACKUP, BOND_MODE_BROADCAST, BOND_MODE_ROUNDROBIN,
    BOND_MODE_XOR, BOND_XMIT_POLICY_LAYER2,
};

fn up(ifindex: u32) -> SlaveState {
    SlaveState { ifindex, link: LinkState::Up, carrier: true, role: SlaveRole::Active,
                 speed_mbps: 1000, ..SlaveState::default() }
}

fn down(ifindex: u32) -> SlaveState {
    SlaveState { ifindex, link: LinkState::Down, carrier: false, role: SlaveRole::Active,
                 ..SlaveState::default() }
}

fn backup(ifindex: u32) -> SlaveState {
    SlaveState { role: SlaveRole::Backup, ..up(ifindex) }
}

fn flow(low_src: u8) -> FlowKeys {
    FlowKeys { dst_mac: [0, 0, 0, 0, 0, 1], src_mac: [0, 0, 0, 0, 0, low_src],
               eth_proto: 0x0800, ..FlowKeys::default() }
}

#[test]
fn slave_id_source_follows_packets_per_slave() {
    assert_eq!(rr_gen_slave_id(0, 7, 0xabcd), 0xabcd);
    assert_eq!(rr_gen_slave_id(1, 7, 0xabcd), 7);
    assert_eq!(rr_gen_slave_id(4, 7, 0xabcd), 1);
    assert_eq!(rr_gen_slave_id(4, 8, 0xabcd), 2);
}

#[test]
fn round_robin_advances_one_slave_per_packet_and_wraps() {
    let s = vec![up(1), up(2), up(3)];
    let seq: Vec<usize> = (1..=7)
        .map(|c| roundrobin_slave(&s, c, 1, false, None, 0).unwrap())
        .collect();
    assert_eq!(seq, vec![1, 2, 0, 1, 2, 0, 1]);
}

#[test]
fn round_robin_holds_a_slave_for_exactly_packets_per_slave_packets() {
    let s = vec![up(1), up(2)];
    let ppl = 3;
    let seq: Vec<usize> = (1..=12)
        .map(|c| roundrobin_slave(&s, c, ppl, false, None, 0).unwrap())
        .collect();
    // The counter divides to 0,0,1,1,1,2,2,2,3,3,3,4 and reduces modulo two.
    assert_eq!(seq, vec![0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0]);
}

#[test]
fn round_robin_skips_a_slave_that_cannot_transmit_and_wraps_back() {
    let s = vec![up(1), down(2), up(3)];
    // Slave-id 1 is unusable, so the walk continues to index 2.
    assert_eq!(roundrobin_slave(&s, 1, 1, false, None, 0), Some(2));
    // Slave-id 2 is usable directly.
    assert_eq!(roundrobin_slave(&s, 2, 1, false, None, 0), Some(2));
    // Slave-id 0 wraps nowhere; index 0 is usable.
    assert_eq!(roundrobin_slave(&s, 3, 1, false, None, 0), Some(0));
}

#[test]
fn the_walk_wraps_from_the_start_when_the_tail_has_nothing_usable() {
    let s = vec![up(1), down(2), down(3)];
    assert_eq!(slave_by_id(&s, 1), Some(0));
    assert_eq!(slave_by_id(&s, 0), Some(0));
    let none = vec![down(1), down(2)];
    assert_eq!(slave_by_id(&none, 0), None);
}

#[test]
fn membership_reports_pin_to_the_active_slave() {
    let s = vec![up(1), up(2), up(3)];
    for c in 1..=5 {
        assert_eq!(roundrobin_slave(&s, c, 1, true, Some(2), 0), Some(2));
    }
    // With no active slave the pin falls back to the first usable one.
    assert_eq!(roundrobin_slave(&s, 9, 1, true, None, 0), Some(0));
}

#[test]
fn a_random_slave_id_is_taken_verbatim_when_packets_per_slave_is_zero() {
    let s = vec![up(1), up(2), up(3)];
    assert_eq!(roundrobin_slave(&s, 999, 0, false, None, 4), Some(1));
    assert_eq!(roundrobin_slave(&s, 999, 0, false, None, 5), Some(2));
}

#[test]
fn active_backup_returns_only_the_active_slave() {
    let s = vec![up(1), backup(2), backup(3)];
    let mut ctx = TxContext { mode: BOND_MODE_ACTIVEBACKUP, curr_active: Some(0),
                              ..TxContext::default() };
    for low in 0..8u8 {
        assert_eq!(select_tx(&s, &ctx, &flow(low)), TxTarget::One(0));
    }
    ctx.curr_active = None;
    assert_eq!(select_tx(&s, &ctx, &flow(0)), TxTarget::None);
}

#[test]
fn broadcast_selects_every_up_slave_and_skips_the_rest() {
    let s = vec![up(1), down(2), backup(3), up(4)];
    // A backup slave still has carrier and a settled link, so it receives a copy.
    assert_eq!(broadcast_slaves(&s), vec![0, 2, 3]);
    let ctx = TxContext { mode: BOND_MODE_BROADCAST, ..TxContext::default() };
    assert_eq!(select_tx(&s, &ctx, &flow(0)), TxTarget::All(vec![0, 2, 3]));
}

#[test]
fn broadcast_with_nothing_up_selects_nothing() {
    let s = vec![down(1), down(2)];
    let ctx = TxContext { mode: BOND_MODE_BROADCAST, ..TxContext::default() };
    assert_eq!(select_tx(&s, &ctx, &flow(0)), TxTarget::None);
}

#[test]
fn xor_reduces_the_hash_over_the_usable_slaves_only() {
    let s = vec![up(1), down(2), up(3)];
    assert_eq!(usable_slaves(&s), vec![0, 2]);
    let ctx = TxContext { mode: BOND_MODE_XOR, xmit_policy: BOND_XMIT_POLICY_LAYER2,
                          ..TxContext::default() };
    for low in 0..16u8 {
        let t = select_tx(&s, &ctx, &flow(low));
        assert!(matches!(t, TxTarget::One(0) | TxTarget::One(2)));
    }
}

#[test]
fn xor_sends_two_flows_with_different_hashes_to_different_slaves() {
    let s = vec![up(1), up(2)];
    let cand = usable_slaves(&s);
    let a = hash_slave(&cand, BOND_XMIT_POLICY_LAYER2, &flow(0)).unwrap();
    let b = hash_slave(&cand, BOND_XMIT_POLICY_LAYER2, &flow(1)).unwrap();
    assert_ne!(a, b);
}

#[test]
fn aggregation_mode_hashes_only_over_the_active_aggregator() {
    let mut s = vec![up(1), up(2), up(3), up(4)];
    s[0].agg_id = 1; s[1].agg_id = 1; s[2].agg_id = 2; s[3].agg_id = 2;
    assert_eq!(aggregator_slaves(&s, 2), vec![2, 3]);
    let ctx = TxContext { mode: BOND_MODE_8023AD, active_agg: 2, ..TxContext::default() };
    for low in 0..16u8 {
        let t = select_tx(&s, &ctx, &flow(low));
        assert!(matches!(t, TxTarget::One(2) | TxTarget::One(3)));
    }
}

#[test]
fn an_aggregator_with_no_usable_port_selects_nothing() {
    let mut s = vec![down(1), down(2)];
    s[0].agg_id = 1; s[1].agg_id = 1;
    let ctx = TxContext { mode: BOND_MODE_8023AD, active_agg: 1, ..TxContext::default() };
    assert_eq!(select_tx(&s, &ctx, &flow(0)), TxTarget::None);
}

#[test]
fn round_robin_through_the_mode_dispatcher_matches_the_direct_call() {
    let s = vec![up(1), up(2), up(3)];
    for c in 1..=6 {
        let ctx = TxContext { mode: BOND_MODE_ROUNDROBIN, rr_counter: c,
                              ..TxContext::default() };
        assert_eq!(select_tx(&s, &ctx, &flow(0)),
                   TxTarget::One(roundrobin_slave(&s, c, 1, false, None, 0).unwrap()));
    }
}
