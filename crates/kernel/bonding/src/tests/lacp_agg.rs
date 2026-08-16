// Aggregator comparison precedence and the ad_select policies.

extern crate alloc;
use alloc::vec;

use crate::lacp::agg::{agg_selection_test, select_aggregator, Aggregator};
use crate::uapi::{BOND_AD_BANDWIDTH, BOND_AD_COUNT, BOND_AD_PRIO, BOND_AD_STABLE};

const PARTNER: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];

fn agg(id: u16) -> Aggregator {
    Aggregator { id, is_individual: false, partner_system: PARTNER, active_ports: 1,
                 ports_priority: 100, bandwidth: 1000, num_ports: 1, actor_key: 7,
                 device_up: true, is_active: false }
}

#[test]
fn with_no_incumbent_the_challenger_takes_the_role() {
    let a = agg(1);
    assert_eq!(agg_selection_test(None, &a, BOND_AD_STABLE).id, 1);
}

#[test]
fn a_negotiated_aggregator_always_beats_an_individual_one() {
    let mut individual = agg(1);
    individual.is_individual = true;
    // The individual group is otherwise better on every policy input.
    individual.active_ports = 8;
    individual.ports_priority = 9999;
    individual.bandwidth = 100_000;
    let negotiated = agg(2);
    for p in [BOND_AD_STABLE, BOND_AD_BANDWIDTH, BOND_AD_COUNT, BOND_AD_PRIO] {
        assert_eq!(agg_selection_test(Some(&individual), &negotiated, p).id, 2);
        assert_eq!(agg_selection_test(Some(&negotiated), &individual, p).id, 2);
    }
}

#[test]
fn an_answering_partner_beats_a_silent_one() {
    let mut silent = agg(1);
    silent.partner_system = [0; 6];
    silent.bandwidth = 100_000;
    let answering = agg(2);
    assert!(!silent.has_partner());
    assert!(answering.has_partner());
    for p in [BOND_AD_STABLE, BOND_AD_BANDWIDTH, BOND_AD_COUNT, BOND_AD_PRIO] {
        assert_eq!(agg_selection_test(Some(&silent), &answering, p).id, 2);
        assert_eq!(agg_selection_test(Some(&answering), &silent, p).id, 2);
    }
}

#[test]
fn the_priority_policy_compares_summed_port_priority() {
    let low = agg(1);
    let mut high = agg(2);
    high.ports_priority = 200;
    assert_eq!(agg_selection_test(Some(&low), &high, BOND_AD_PRIO).id, 2);
    assert_eq!(agg_selection_test(Some(&high), &low, BOND_AD_PRIO).id, 2);
}

#[test]
fn the_priority_policy_falls_back_to_port_count_on_a_tie() {
    let one = agg(1);
    let mut many = agg(2);
    many.active_ports = 4;
    // Equal priority, so the count decides.
    assert_eq!(many.ports_priority, one.ports_priority);
    assert_eq!(agg_selection_test(Some(&one), &many, BOND_AD_PRIO).id, 2);
    assert_eq!(agg_selection_test(Some(&many), &one, BOND_AD_PRIO).id, 2);
}

#[test]
fn the_priority_policy_falls_through_to_bandwidth_when_priority_and_count_tie() {
    let slow = agg(1);
    let mut fast = agg(2);
    fast.bandwidth = 10_000;
    assert_eq!(agg_selection_test(Some(&slow), &fast, BOND_AD_PRIO).id, 2);
    assert_eq!(agg_selection_test(Some(&fast), &slow, BOND_AD_PRIO).id, 2);
}

#[test]
fn the_count_policy_ignores_priority_and_compares_ports() {
    let mut high_prio = agg(1);
    high_prio.ports_priority = 60000;
    let mut many = agg(2);
    many.active_ports = 3;
    assert_eq!(agg_selection_test(Some(&high_prio), &many, BOND_AD_COUNT).id, 2);
}

#[test]
fn the_count_policy_falls_back_to_bandwidth_on_a_tie() {
    let slow = agg(1);
    let mut fast = agg(2);
    fast.bandwidth = 5000;
    assert_eq!(agg_selection_test(Some(&slow), &fast, BOND_AD_COUNT).id, 2);
}

#[test]
fn the_bandwidth_policy_ignores_priority_and_count() {
    let mut wide = agg(1);
    wide.bandwidth = 40_000;
    let mut busy = agg(2);
    busy.active_ports = 16;
    busy.ports_priority = 60000;
    for p in [BOND_AD_BANDWIDTH, BOND_AD_STABLE] {
        assert_eq!(agg_selection_test(Some(&wide), &busy, p).id, 1);
        assert_eq!(agg_selection_test(Some(&busy), &wide, p).id, 1);
    }
}

#[test]
fn an_exact_tie_keeps_the_incumbent() {
    let a = agg(1);
    let b = agg(2);
    for p in [BOND_AD_STABLE, BOND_AD_BANDWIDTH, BOND_AD_COUNT, BOND_AD_PRIO] {
        assert_eq!(agg_selection_test(Some(&a), &b, p).id, 1);
    }
}

#[test]
fn selection_skips_groups_with_no_active_port_or_no_live_device() {
    let mut dead = agg(1);
    dead.device_up = false;
    dead.bandwidth = 100_000;
    let mut empty = agg(2);
    empty.active_ports = 0;
    empty.bandwidth = 100_000;
    let live = agg(3);
    let aggs = vec![dead, empty, live];
    assert_eq!(select_aggregator(&aggs, BOND_AD_BANDWIDTH), Some(2));
}

#[test]
fn the_stable_policy_keeps_an_incumbent_that_still_has_an_answering_partner() {
    let mut incumbent = agg(1);
    incumbent.is_active = true;
    let mut better = agg(2);
    better.bandwidth = 100_000;
    let aggs = vec![incumbent, better];
    assert_eq!(select_aggregator(&aggs, BOND_AD_STABLE), Some(0));
    // The bandwidth policy has no such stickiness.
    assert_eq!(select_aggregator(&aggs, BOND_AD_BANDWIDTH), Some(1));
}

#[test]
fn the_stable_policy_releases_an_incumbent_whose_ports_are_gone() {
    let mut incumbent = agg(1);
    incumbent.is_active = true;
    incumbent.active_ports = 0;
    incumbent.num_ports = 0;
    // With no ports attached the group has no live device behind it either.
    incumbent.device_up = false;
    let better = agg(2);
    let aggs = vec![incumbent, better];
    assert_eq!(select_aggregator(&aggs, BOND_AD_STABLE), Some(1));
}

#[test]
fn the_stable_policy_yields_when_the_incumbent_has_no_aggregation_key() {
    let mut incumbent = agg(1);
    incumbent.is_active = true;
    incumbent.actor_key = 0;
    let mut better = agg(2);
    better.bandwidth = 100_000;
    let aggs = vec![incumbent, better];
    assert_eq!(select_aggregator(&aggs, BOND_AD_STABLE), Some(1));
}

#[test]
fn an_empty_bond_selects_nothing() {
    assert_eq!(select_aggregator(&[], BOND_AD_STABLE), None);
}
