// MII monitor phase machine and ARP monitor validation.

extern crate alloc;
use alloc::vec;

use crate::link::{
    arp_filtered, arp_missed_exceeded, arp_rcv, arp_targets_satisfied, arp_validate_disabled,
    arp_validate_for_role, ignore_updelay, mii_inspect, mii_tick, ArpAccept, ArpRxContext,
    MiiParams,
};
use crate::slave::{LinkState, SlaveRole, SlaveState};
use crate::uapi::{
    BOND_ARP_FILTER, BOND_ARP_FILTER_ACTIVE, BOND_ARP_FILTER_BACKUP, BOND_ARP_TARGETS_ALL,
    BOND_ARP_TARGETS_ANY, BOND_ARP_VALIDATE_ACTIVE, BOND_ARP_VALIDATE_ALL,
    BOND_ARP_VALIDATE_BACKUP, BOND_ARP_VALIDATE_NONE, BOND_MODE_ACTIVEBACKUP, BOND_MODE_XOR,
};

fn slave(link: LinkState, carrier: bool, delay: i32) -> SlaveState {
    SlaveState { link, carrier, delay, role: SlaveRole::Active, ..SlaveState::default() }
}

/// Drive one slave through `ticks` monitor passes, committing each proposal.
fn run(mut s: SlaveState, params: MiiParams, carrier: &[bool], ignore_up: bool)
    -> alloc::vec::Vec<LinkState>
{
    let mut out = alloc::vec::Vec::new();
    for c in carrier {
        s.carrier = *c;
        let p = mii_tick(&s, &params, ignore_up);
        if let Some(l) = p.link { s.link = l; }
        s.delay = p.delay;
        out.push(s.link);
    }
    out
}

#[test]
fn a_carrier_loss_walks_up_fail_down_over_the_down_delay() {
    let p = MiiParams { downdelay: 3, updelay: 0 };
    let seq = run(slave(LinkState::Up, true, 0), p, &[false, false, false, false], false);
    // Entering FAIL consumes one tick of the delay, so DOWN lands on tick 4.
    assert_eq!(seq, vec![LinkState::Fail, LinkState::Fail, LinkState::Fail, LinkState::Down]);
}

#[test]
fn a_link_that_returns_before_the_down_delay_expires_goes_straight_back_up() {
    let p = MiiParams { downdelay: 5, updelay: 0 };
    let seq = run(slave(LinkState::Up, true, 0), p, &[false, false, true], false);
    assert_eq!(seq, vec![LinkState::Fail, LinkState::Fail, LinkState::Up]);
}

#[test]
fn a_zero_down_delay_drops_the_link_on_the_same_tick() {
    let p = MiiParams { downdelay: 0, updelay: 0 };
    let seq = run(slave(LinkState::Up, true, 0), p, &[false], false);
    assert_eq!(seq, vec![LinkState::Down]);
}

#[test]
fn a_recovering_link_waits_out_the_whole_up_delay() {
    let p = MiiParams { downdelay: 0, updelay: 3 };
    let seq = run(slave(LinkState::Down, false, 0), p, &[true, true, true, true], false);
    assert_eq!(seq, vec![LinkState::Back, LinkState::Back, LinkState::Back, LinkState::Up]);
}

#[test]
fn a_recovering_link_that_flaps_returns_to_down_without_finishing_the_up_delay() {
    let p = MiiParams { downdelay: 0, updelay: 4 };
    let seq = run(slave(LinkState::Down, false, 0), p, &[true, true, false], false);
    assert_eq!(seq, vec![LinkState::Back, LinkState::Back, LinkState::Down]);
}

#[test]
fn a_bond_with_no_working_path_skips_the_up_delay_entirely() {
    let p = MiiParams { downdelay: 0, updelay: 10 };
    let seq = run(slave(LinkState::Down, false, 0), p, &[true], true);
    assert_eq!(seq, vec![LinkState::Up]);
}

#[test]
fn the_up_delay_is_honoured_once_the_bond_has_a_path_again() {
    let p = MiiParams { downdelay: 0, updelay: 10 };
    let seq = run(slave(LinkState::Down, false, 0), p, &[true], false);
    assert_eq!(seq, vec![LinkState::Back]);
}

#[test]
fn a_full_cycle_returns_to_up_with_both_delays_honoured() {
    let p = MiiParams { downdelay: 2, updelay: 2 };
    let mut s = slave(LinkState::Up, true, 0);
    let carrier = [true, false, false, false, true, true, true];
    let mut seen = alloc::vec::Vec::new();
    for c in carrier {
        s.carrier = c;
        let prop = mii_tick(&s, &p, false);
        if let Some(l) = prop.link { s.link = l; }
        s.delay = prop.delay;
        seen.push(s.link);
    }
    assert_eq!(seen, vec![
        LinkState::Up, LinkState::Fail, LinkState::Fail, LinkState::Down,
        LinkState::Back, LinkState::Back, LinkState::Up,
    ]);
}

#[test]
fn an_unchanged_up_link_proposes_nothing() {
    let p = MiiParams { downdelay: 2, updelay: 2 };
    let prop = mii_tick(&slave(LinkState::Up, true, 0), &p, false);
    assert_eq!(prop.link, None);
    assert!(!prop.commit);
}

#[test]
fn the_up_delay_skip_is_decided_per_mode() {
    let ups = vec![slave(LinkState::Up, true, 0)];
    let downs = vec![slave(LinkState::Down, false, 0)];
    assert!(ignore_updelay(BOND_MODE_ACTIVEBACKUP, &ups, None));
    assert!(!ignore_updelay(BOND_MODE_ACTIVEBACKUP, &ups, Some(0)));
    assert!(!ignore_updelay(BOND_MODE_XOR, &ups, None));
    assert!(ignore_updelay(BOND_MODE_XOR, &downs, None));
}

#[test]
fn once_one_slave_comes_up_the_rest_stop_skipping_their_up_delay() {
    let p = MiiParams { downdelay: 0, updelay: 5 };
    let slaves = vec![
        slave(LinkState::Down, true, 0),
        slave(LinkState::Down, true, 0),
    ];
    let props = mii_inspect(&slaves, &p, BOND_MODE_XOR, None);
    assert_eq!(props[0].link, Some(LinkState::Up));
    assert_eq!(props[1].link, Some(LinkState::Back));
    assert_eq!(props[1].delay, 4);
}

// ------------------------------------------------------------------ ARP monitor

fn arp(ctx: ArpRxContext) -> ArpRxContext {
    ArpRxContext { hlen_ok: true, plen_ok: true, types_ok: true, addressed_here: true, ..ctx }
}

#[test]
fn an_arp_on_the_active_slave_validates_as_received() {
    let c = arp(ArpRxContext { slave_is_active: true, ..ArpRxContext::default() });
    assert_eq!(arp_rcv(&c), ArpAccept::OnActive);
}

#[test]
fn a_backup_slave_validates_the_request_with_sender_and_target_swapped() {
    let c = arp(ArpRxContext { slave_is_active: false, have_active: true,
                               active_rx_since_up: true, ..ArpRxContext::default() });
    assert_eq!(arp_rcv(&c), ArpAccept::OnBackupSwapped);
}

#[test]
fn a_backup_slave_with_a_silent_active_slave_validates_nothing() {
    let c = arp(ArpRxContext { have_active: true, active_rx_since_up: false,
                               ..ArpRxContext::default() });
    assert_eq!(arp_rcv(&c), ArpAccept::No);
}

#[test]
fn a_probe_reply_validates_on_any_slave_but_only_a_reply_does() {
    let base = ArpRxContext { have_arp_slave: true, arp_slave_tx_in_interval: true,
                              ..ArpRxContext::default() };
    assert_eq!(arp_rcv(&arp(ArpRxContext { is_reply: true, ..base })), ArpAccept::ProbeReply);
    assert_eq!(arp_rcv(&arp(ArpRxContext { is_reply: false, ..base })), ArpAccept::No);
    assert_eq!(arp_rcv(&arp(ArpRxContext { is_reply: true, arp_slave_tx_in_interval: false,
                                           ..base })), ArpAccept::No);
}

#[test]
fn a_malformed_or_overheard_frame_is_rejected_before_any_rule_runs() {
    let good = ArpRxContext { slave_is_active: true, ..ArpRxContext::default() };
    assert_eq!(arp_rcv(&arp(good)), ArpAccept::OnActive);
    for bad in [
        ArpRxContext { hlen_ok: false, ..arp(good) },
        ArpRxContext { plen_ok: false, ..arp(good) },
        ArpRxContext { types_ok: false, ..arp(good) },
        ArpRxContext { addressed_here: false, ..arp(good) },
    ] {
        assert_eq!(arp_rcv(&bad), ArpAccept::No);
    }
}

#[test]
fn the_validate_matrix_selects_roles_and_the_filter_bit_independently() {
    let rows: [(u32, bool, bool, bool); 7] = [
        // value, validates active, validates backup, filters
        (BOND_ARP_VALIDATE_NONE, false, false, false),
        (BOND_ARP_VALIDATE_ACTIVE, true, false, false),
        (BOND_ARP_VALIDATE_BACKUP, false, true, false),
        (BOND_ARP_VALIDATE_ALL, true, true, false),
        (BOND_ARP_FILTER, false, false, true),
        (BOND_ARP_FILTER_ACTIVE, true, false, true),
        (BOND_ARP_FILTER_BACKUP, false, true, true),
    ];
    for (v, act, bak, filt) in rows {
        assert_eq!(arp_validate_for_role(v, true), act);
        assert_eq!(arp_validate_for_role(v, false), bak);
        assert_eq!(arp_filtered(v), filt);
    }
    assert!(arp_validate_disabled(BOND_ARP_VALIDATE_NONE));
    assert!(!arp_validate_disabled(BOND_ARP_FILTER));
}

#[test]
fn any_needs_one_reply_and_all_needs_every_target() {
    assert!(arp_targets_satisfied(BOND_ARP_TARGETS_ANY, &[false, true, false]));
    assert!(!arp_targets_satisfied(BOND_ARP_TARGETS_ANY, &[false, false]));
    assert!(!arp_targets_satisfied(BOND_ARP_TARGETS_ALL, &[true, false]));
    assert!(arp_targets_satisfied(BOND_ARP_TARGETS_ALL, &[true, true]));
    assert!(!arp_targets_satisfied(BOND_ARP_TARGETS_ANY, &[]));
    assert!(!arp_targets_satisfied(BOND_ARP_TARGETS_ALL, &[]));
}

#[test]
fn a_link_stays_up_until_the_missed_count_passes_the_maximum() {
    assert!(!arp_missed_exceeded(2, 2));
    assert!(arp_missed_exceeded(3, 2));
}
