// IFLA_BOND_* attribute parsing and the pre-apply dependency sweep.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use syscall::Errno;

use crate::netlink::{check_all, parse, parse_and_check, validate_value, OptionWrite};
use crate::options::{
    BondStateView, BOND_OPT_LACP_RATE, BOND_OPT_MIIMON, BOND_OPT_MODE,
    BOND_OPT_PACKETS_PER_SLAVE, BOND_OPT_XMIT_HASH,
};
use crate::uapi::{
    BOND_MODE_8023AD, BOND_MODE_ACTIVEBACKUP, BOND_MODE_MAX, BOND_MODE_ROUNDROBIN,
    BOND_XMIT_POLICY_LAYER34, BOND_XMIT_POLICY_MAX, IFLA_BOND_AD_INFO,
    IFLA_BOND_AD_LACP_RATE, IFLA_BOND_ARP_IP_TARGET, IFLA_BOND_MIIMON, IFLA_BOND_MODE,
    IFLA_BOND_PACKETS_PER_SLAVE, IFLA_BOND_XMIT_HASH_POLICY,
};

/// Build one attribute: length, type, payload, padded to the alignment.
fn attr(typ: u16, payload: &[u8]) -> Vec<u8> {
    let len = 4 + payload.len();
    let mut v = Vec::new();
    v.extend_from_slice(&(len as u16).to_ne_bytes());
    v.extend_from_slice(&typ.to_ne_bytes());
    v.extend_from_slice(payload);
    while v.len() % 4 != 0 { v.push(0); }
    v
}

fn state(mode: u8, has_slaves: bool, if_up: bool) -> BondStateView {
    BondStateView { mode, has_slaves, if_up }
}

#[test]
fn an_empty_blob_yields_no_writes() {
    assert_eq!(parse(&[]), Ok(Vec::new()));
}

#[test]
fn integer_attributes_are_read_at_their_declared_width() {
    let mut blob = attr(IFLA_BOND_MODE, &[BOND_MODE_8023AD]);
    blob.extend(attr(IFLA_BOND_MIIMON, &100u32.to_ne_bytes()));
    blob.extend(attr(IFLA_BOND_XMIT_HASH_POLICY, &[BOND_XMIT_POLICY_LAYER34]));
    let w = parse(&blob).unwrap();
    assert_eq!(w.len(), 3);
    assert_eq!(w[0], OptionWrite { opt_id: BOND_OPT_MODE, value: BOND_MODE_8023AD as u64,
                                   raw: Vec::new() });
    assert_eq!(w[1], OptionWrite { opt_id: BOND_OPT_MIIMON, value: 100, raw: Vec::new() });
    assert_eq!(w[2].opt_id, BOND_OPT_XMIT_HASH);
    assert_eq!(w[2].value, BOND_XMIT_POLICY_LAYER34 as u64);
}

#[test]
fn a_raw_valued_attribute_carries_its_payload_through() {
    let blob = attr(IFLA_BOND_ARP_IP_TARGET, &[10, 0, 0, 1, 10, 0, 0, 2]);
    let w = parse(&blob).unwrap();
    assert_eq!(w.len(), 1);
    assert_eq!(w[0].raw, vec![10, 0, 0, 1, 10, 0, 0, 2]);
    assert_eq!(w[0].value, 0);
}

#[test]
fn the_read_only_aggregation_block_is_not_a_write() {
    let mut blob = attr(IFLA_BOND_AD_INFO, &[0, 0, 0, 0]);
    blob.extend(attr(IFLA_BOND_MIIMON, &50u32.to_ne_bytes()));
    let w = parse(&blob).unwrap();
    assert_eq!(w.len(), 1);
    assert_eq!(w[0].opt_id, BOND_OPT_MIIMON);
}

#[test]
fn an_unknown_attribute_fails_the_parse() {
    let blob = attr(0xfff0, &[0]);
    assert_eq!(parse(&blob), Err(Errno::Einval));
}

#[test]
fn a_short_payload_for_a_wide_attribute_fails_the_parse() {
    let blob = attr(IFLA_BOND_MIIMON, &[1, 2]);
    assert_eq!(parse(&blob), Err(Errno::Einval));
}

#[test]
fn a_length_field_running_past_the_blob_fails_the_parse() {
    let mut blob = attr(IFLA_BOND_MIIMON, &100u32.to_ne_bytes());
    blob[0] = 200;
    assert_eq!(parse(&blob), Err(Errno::Einval));
    let mut zero = blob.clone();
    zero[0] = 0; zero[1] = 0;
    assert_eq!(parse(&zero), Err(Errno::Einval));
}

#[test]
fn out_of_range_values_are_refused() {
    for (id, bad) in [(BOND_OPT_MODE, BOND_MODE_MAX as u64 + 1),
                      (BOND_OPT_XMIT_HASH, BOND_XMIT_POLICY_MAX as u64 + 1),
                      (BOND_OPT_PACKETS_PER_SLAVE, 65536)] {
        let w = OptionWrite { opt_id: id, value: bad, raw: Vec::new() };
        assert_eq!(validate_value(&w), Err(Errno::Einval));
    }
    let ok = OptionWrite { opt_id: BOND_OPT_MODE, value: BOND_MODE_MAX as u64,
                           raw: Vec::new() };
    assert_eq!(validate_value(&ok), Ok(()));
}

#[test]
fn a_write_the_current_mode_refuses_is_a_permission_failure() {
    let blob = attr(IFLA_BOND_PACKETS_PER_SLAVE, &4u32.to_ne_bytes());
    assert_eq!(parse_and_check(&blob, &state(BOND_MODE_ROUNDROBIN, false, false))
                   .map(|w| w.len()), Ok(1));
    assert_eq!(parse_and_check(&blob, &state(BOND_MODE_ACTIVEBACKUP, false, false)),
               Err(Errno::Eacces));
}

#[test]
fn a_mode_change_in_the_same_request_governs_the_later_writes() {
    let mut blob = attr(IFLA_BOND_MODE, &[BOND_MODE_8023AD]);
    blob.extend(attr(IFLA_BOND_AD_LACP_RATE, &[1]));
    // The aggregation option is legal because the same request selects that mode.
    let w = parse_and_check(&blob, &state(BOND_MODE_ROUNDROBIN, false, false)).unwrap();
    assert_eq!(w.len(), 2);
    assert_eq!(w[1].opt_id, BOND_OPT_LACP_RATE);

    // Without the mode change it is refused.
    let alone = attr(IFLA_BOND_AD_LACP_RATE, &[1]);
    assert_eq!(parse_and_check(&alone, &state(BOND_MODE_ROUNDROBIN, false, false)),
               Err(Errno::Eacces));
}

#[test]
fn a_mode_change_on_a_populated_bond_reports_that_the_bond_is_not_empty() {
    let blob = attr(IFLA_BOND_MODE, &[BOND_MODE_8023AD]);
    assert_eq!(parse_and_check(&blob, &state(BOND_MODE_ROUNDROBIN, true, false)),
               Err(Errno::Enotempty));
}

#[test]
fn an_option_needing_a_down_bond_is_refused_while_it_is_up() {
    let blob = attr(IFLA_BOND_AD_LACP_RATE, &[1]);
    assert_eq!(parse_and_check(&blob, &state(BOND_MODE_8023AD, false, true)),
               Err(Errno::Ebusy));
    assert!(parse_and_check(&blob, &state(BOND_MODE_8023AD, false, false)).is_ok());
}

#[test]
fn the_whole_request_is_rejected_when_any_write_is_illegal() {
    let mut blob = attr(IFLA_BOND_MIIMON, &100u32.to_ne_bytes());
    blob.extend(attr(IFLA_BOND_AD_LACP_RATE, &[1]));
    assert_eq!(parse_and_check(&blob, &state(BOND_MODE_ROUNDROBIN, false, false)),
               Err(Errno::Eacces));
}

#[test]
fn the_sweep_reports_the_same_verdict_as_a_direct_check() {
    let writes = vec![OptionWrite { opt_id: BOND_OPT_LACP_RATE, value: 1, raw: Vec::new() }];
    assert_eq!(check_all(&writes, &state(BOND_MODE_8023AD, false, false)), Ok(()));
    assert_eq!(check_all(&writes, &state(BOND_MODE_8023AD, false, true)), Err(Errno::Ebusy));
    assert_eq!(check_all(&writes, &state(BOND_MODE_XOR_FOR_TEST, false, false)),
               Err(Errno::Eacces));
}

const BOND_MODE_XOR_FOR_TEST: u8 = crate::uapi::BOND_MODE_XOR;
