// The `ct` key set. A wrong answer here is the dangerous direction: a rule
// that admits ESTABLISHED traffic must not admit a packet with no entry, and
// a template must not read as a live flow.

extern crate alloc;
use alloc::vec;

use conntrack::uapi::{IP_CT_ESTABLISHED, IP_CT_ESTABLISHED_REPLY, IP_CT_NEW, IP_CT_RELATED,
                      IP_CT_RELATED_REPLY, IP_CT_UNTRACKED, IPCT_MARK, IPCT_SECMARK,
                      IPS_ASSURED, IPS_SEEN_REPLY};

use crate::nft_expr::ctx::EvalCtx;
use crate::nft_expr::expr::Expr;
use crate::nft_expr::run::ct::state_bit;
use crate::nft_expr::run::run_rule_ctx;
use crate::nft_expr::stateful::ExprStates;
use crate::nft_expr::uapi::*;
use super::fixture::{self, Ct};

/// Load one `ct` key into register 1, compare it against `want`, then drop.
/// A rule that reaches the drop matched; one that does not, did not.
fn ct_match(key: u32, dir: Option<u8>, len: u32, want: &[u8]) -> alloc::vec::Vec<Expr> {
    vec![
        Expr::Ct { dreg: Some(NFT_REG_1), sreg: None, key, dir, len },
        Expr::Cmp { sreg: NFT_REG_1, op: NFT_CMP_EQ, data: want.to_vec() },
        Expr::Immediate { dreg: NFT_REG_VERDICT, verdict: Some(NF_DROP), chain: None,
                          value: alloc::vec::Vec::new() },
    ]
}

fn run<'a>(exprs: &[Expr], ct: Option<&'a Ct>) -> i32 {
    let states = ExprStates::for_exprs(exprs);
    let pkt = fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &[]);
    let mut ctx = EvalCtx::ipv4(&pkt, &states);
    ctx.ct = ct.map(|c| c as &dyn crate::nft_expr::access::CtAccess);
    run_rule_ctx(exprs, &mut ctx).code
}

#[test]
fn state_bits_are_the_documented_powers_of_two() {
    // A tracked packet's bit is derived from its conntrack-info; the two
    // untracked forms are separate bits that no tracked packet ever sets.
    assert_eq!(state_bit(true, IP_CT_NEW), 1 << 3);
    assert_eq!(state_bit(true, IP_CT_ESTABLISHED), 1 << 1);
    assert_eq!(state_bit(true, IP_CT_RELATED), 1 << 2);
    assert_eq!(state_bit(true, IP_CT_ESTABLISHED_REPLY), 1 << 1);
    assert_eq!(state_bit(true, IP_CT_RELATED_REPLY), 1 << 2);
    assert_eq!(state_bit(false, IP_CT_UNTRACKED), NF_CT_STATE_UNTRACKED_BIT);
    assert_eq!(state_bit(false, IP_CT_NEW), NF_CT_STATE_INVALID_BIT);
}

#[test]
fn an_untracked_packet_never_reads_as_established() {
    // The whole point of a stateful accept rule. A packet with no entry must
    // not satisfy `ct state established`, or the ruleset admits anything.
    let established = state_bit(true, IP_CT_ESTABLISHED);
    let rule = ct_match(NFT_CT_STATE, None, 4, &established.to_ne_bytes());

    let live = Ct { ctinfo: IP_CT_ESTABLISHED, attached: true, ..Ct::default() };
    assert_eq!(run(&rule, Some(&live)), NF_DROP, "the tracked flow matches");

    // A non-matching comparison ends the rule, so the drop is never reached.
    let untracked = Ct { ctinfo: IP_CT_UNTRACKED, attached: false, ..Ct::default() };
    assert_eq!(run(&rule, Some(&untracked)), NFT_BREAK);

    let invalid = Ct { ctinfo: IP_CT_NEW, attached: false, ..Ct::default() };
    assert_eq!(run(&rule, Some(&invalid)), NFT_BREAK);

    // And each reads as its own state, not as a tracked one.
    let untracked_bit = state_bit(false, IP_CT_UNTRACKED);
    let by_bit = ct_match(NFT_CT_STATE, None, 4, &untracked_bit.to_ne_bytes());
    assert_eq!(run(&by_bit, Some(&untracked)), NF_DROP);
    assert_ne!(untracked_bit, established);
}

#[test]
fn a_new_packet_never_reads_as_established() {
    let established = state_bit(true, IP_CT_ESTABLISHED);
    let rule = ct_match(NFT_CT_STATE, None, 4, &established.to_ne_bytes());
    let fresh = Ct { ctinfo: IP_CT_NEW, attached: true, ..Ct::default() };
    assert_eq!(run(&rule, Some(&fresh)), NFT_BREAK);
}

#[test]
fn with_no_conntrack_at_all_every_key_breaks() {
    // Not "reads zero": a zero would satisfy a rule testing for a zero mark.
    for key in [NFT_CT_STATE, NFT_CT_MARK, NFT_CT_STATUS, NFT_CT_ID, NFT_CT_ZONE] {
        let rule = ct_match(key, None, 4, &0u32.to_ne_bytes());
        assert_eq!(run(&rule, None), NFT_BREAK, "key {key}");
    }
}

#[test]
fn a_template_carries_no_per_flow_state() {
    // A template exists to attach policy to a flow that has not been created
    // yet; reading its mark or counters as a flow's own would be a fabrication.
    let tmpl = Ct { ctinfo: IP_CT_NEW, attached: true, template: true,
                    mark: core::cell::Cell::new(0x99), ..Ct::default() };
    let rule = ct_match(NFT_CT_MARK, None, 4, &0x99u32.to_ne_bytes());
    assert_eq!(run(&rule, Some(&tmpl)), NFT_BREAK);
    // The state key still answers, because a template's state is a real state.
    let state = ct_match(NFT_CT_STATE, None, 4, &state_bit(true, IP_CT_NEW).to_ne_bytes());
    assert_eq!(run(&state, Some(&tmpl)), NF_DROP);
}

#[test]
fn scalar_keys_report_their_own_widths() {
    let ct = Ct { ctinfo: IP_CT_ESTABLISHED, attached: true,
                  status: IPS_SEEN_REPLY | IPS_ASSURED,
                  mark: core::cell::Cell::new(0xdead_beef),
                  secmark: core::cell::Cell::new(7),
                  expiration_ms: 30_000, zone: 0x1234, id: 42, ..Ct::default() };
    assert_eq!(run(&ct_match(NFT_CT_STATUS, None, 4,
        &(IPS_SEEN_REPLY | IPS_ASSURED).to_ne_bytes()), Some(&ct)), NF_DROP);
    assert_eq!(run(&ct_match(NFT_CT_MARK, None, 4, &0xdead_beefu32.to_ne_bytes()),
        Some(&ct)), NF_DROP);
    assert_eq!(run(&ct_match(NFT_CT_SECMARK, None, 4, &7u32.to_ne_bytes()),
        Some(&ct)), NF_DROP);
    assert_eq!(run(&ct_match(NFT_CT_EXPIRATION, None, 4, &30_000u32.to_ne_bytes()),
        Some(&ct)), NF_DROP);
    assert_eq!(run(&ct_match(NFT_CT_ID, None, 4, &42u32.to_ne_bytes()), Some(&ct)), NF_DROP);
    // The zone is sixteen bits; comparing four would read a neighbouring one.
    assert_eq!(run(&ct_match(NFT_CT_ZONE, None, 2, &0x1234u16.to_ne_bytes()),
        Some(&ct)), NF_DROP);
    assert_eq!(run(&ct_match(NFT_CT_DIRECTION, None, 1, &[0]), Some(&ct)), NF_DROP);
}

#[test]
fn the_direction_key_follows_the_packet() {
    let reply = Ct { ctinfo: IP_CT_ESTABLISHED_REPLY, attached: true, ..Ct::default() };
    assert_eq!(run(&ct_match(NFT_CT_DIRECTION, None, 1, &[1]), Some(&reply)), NF_DROP);
    assert_eq!(run(&ct_match(NFT_CT_DIRECTION, None, 1, &[0]), Some(&reply)), NFT_BREAK);
}

#[test]
fn address_keys_read_the_named_direction_not_the_packets() {
    let ct = Ct {
        ctinfo: IP_CT_ESTABLISHED, attached: true,
        tuples: [Some(fixture::tuple4([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80)),
                 Some(fixture::tuple4([93, 184, 216, 34], 80, [203, 0, 113, 5], 40000))],
        ..Ct::default()
    };
    // Original source is the client; reply source is the server. A rule that
    // named a direction must get that direction, not the packet's.
    assert_eq!(run(&ct_match(NFT_CT_SRC, Some(0), 4, &[10, 0, 0, 1]), Some(&ct)), NF_DROP);
    assert_eq!(run(&ct_match(NFT_CT_SRC, Some(1), 4, &[93, 184, 216, 34]),
        Some(&ct)), NF_DROP);
    assert_eq!(run(&ct_match(NFT_CT_DST, Some(1), 4, &[203, 0, 113, 5]), Some(&ct)), NF_DROP);
    assert_eq!(run(&ct_match(NFT_CT_PROTO_DST, Some(0), 2, &80u16.to_be_bytes()),
        Some(&ct)), NF_DROP);
    assert_eq!(run(&ct_match(NFT_CT_PROTO_SRC, Some(1), 2, &80u16.to_be_bytes()),
        Some(&ct)), NF_DROP);
    assert_eq!(run(&ct_match(NFT_CT_PROTOCOL, Some(0), 1,
        &[conntrack::uapi::IPPROTO_TCP]), Some(&ct)), NF_DROP);
    assert_eq!(run(&ct_match(NFT_CT_L3PROTOCOL, Some(0), 1,
        &[conntrack::uapi::NFPROTO_IPV4]), Some(&ct)), NF_DROP);
}

#[test]
fn an_absent_tuple_breaks_rather_than_reading_zeroes() {
    let ct = Ct { ctinfo: IP_CT_ESTABLISHED, attached: true, tuples: [None, None],
                  ..Ct::default() };
    assert_eq!(run(&ct_match(NFT_CT_SRC, Some(0), 4, &[0, 0, 0, 0]), Some(&ct)), NFT_BREAK);
}

#[test]
fn a_family_specific_address_key_refuses_the_other_family() {
    let ct = Ct {
        ctinfo: IP_CT_ESTABLISHED, attached: true,
        tuples: [Some(fixture::tuple4([10, 0, 0, 1], 1, [10, 0, 0, 2], 2)), None],
        ..Ct::default()
    };
    assert_eq!(run(&ct_match(NFT_CT_SRC_IP, Some(0), 4, &[10, 0, 0, 1]), Some(&ct)), NF_DROP);
    // The v6 form must not silently read the v4 address's first bytes.
    assert_eq!(run(&ct_match(NFT_CT_SRC_IP6, Some(0), 16, &[0u8; 16]), Some(&ct)), NFT_BREAK);
}

#[test]
fn counter_keys_sum_the_directions_the_rule_named() {
    let ct = Ct { ctinfo: IP_CT_ESTABLISHED, attached: true,
                  counters: [(10, 1000), (4, 400)], ..Ct::default() };
    assert_eq!(run(&ct_match(NFT_CT_PKTS, Some(0), 8, &10u64.to_ne_bytes()),
        Some(&ct)), NF_DROP);
    assert_eq!(run(&ct_match(NFT_CT_BYTES, Some(1), 8, &400u64.to_ne_bytes()),
        Some(&ct)), NF_DROP);
    // With no direction named, both halves are summed.
    assert_eq!(run(&ct_match(NFT_CT_PKTS, Some(2), 8, &14u64.to_ne_bytes()),
        Some(&ct)), NF_DROP);
    assert_eq!(run(&ct_match(NFT_CT_BYTES, Some(2), 8, &1400u64.to_ne_bytes()),
        Some(&ct)), NF_DROP);
    // Average is bytes over packets, both directions.
    assert_eq!(run(&ct_match(NFT_CT_AVGPKT, Some(2), 8, &100u64.to_ne_bytes()),
        Some(&ct)), NF_DROP);
}

#[test]
fn an_average_over_no_packets_is_zero_not_a_division_fault() {
    let ct = Ct { ctinfo: IP_CT_ESTABLISHED, attached: true, counters: [(0, 0), (0, 0)],
                  ..Ct::default() };
    assert_eq!(run(&ct_match(NFT_CT_AVGPKT, Some(0), 8, &0u64.to_ne_bytes()),
        Some(&ct)), NF_DROP);
}

#[test]
fn the_helper_key_breaks_when_no_helper_is_attached() {
    let mut name = [0u8; crate::nft_expr::limits::NF_CT_HELPER_NAME_LEN];
    name[..3].copy_from_slice(b"ftp");
    let with = Ct { ctinfo: IP_CT_ESTABLISHED, attached: true, helper: Some(name),
                    ..Ct::default() };
    assert_eq!(run(&ct_match(NFT_CT_HELPER, None, 16, &name), Some(&with)), NF_DROP);
    let without = Ct { ctinfo: IP_CT_ESTABLISHED, attached: true, ..Ct::default() };
    assert_eq!(run(&ct_match(NFT_CT_HELPER, None, 16, &name), Some(&without)), NFT_BREAK);
}

#[test]
fn labels_read_as_zero_so_absence_is_testable() {
    let ct = Ct { ctinfo: IP_CT_ESTABLISHED, attached: true, ..Ct::default() };
    let zero = [0u8; crate::nft_expr::limits::NF_CT_LABELS_MAX_SIZE];
    assert_eq!(run(&ct_match(NFT_CT_LABELS, None, zero.len() as u32, &zero),
        Some(&ct)), NF_DROP);
}

#[test]
fn setting_a_mark_writes_it_through_and_caches_the_event() {
    let ct = Ct { ctinfo: IP_CT_ESTABLISHED, attached: true, ..Ct::default() };
    let exprs = vec![
        Expr::Immediate { dreg: NFT_REG_1, verdict: None, chain: None,
                          value: 0x55u32.to_ne_bytes().to_vec() },
        Expr::Ct { dreg: None, sreg: Some(NFT_REG_1), key: NFT_CT_MARK, dir: None, len: 4 },
    ];
    assert_eq!(run(&exprs, Some(&ct)), NFT_CONTINUE, "a set never sets a verdict");
    assert_eq!(ct.mark.get(), 0x55);
    assert_eq!(ct.events.get() & IPCT_MARK, IPCT_MARK);
}

#[test]
fn setting_a_secmark_writes_it_through() {
    let ct = Ct { ctinfo: IP_CT_ESTABLISHED, attached: true, ..Ct::default() };
    let exprs = vec![
        Expr::Immediate { dreg: NFT_REG_1, verdict: None, chain: None,
                          value: 9u32.to_ne_bytes().to_vec() },
        Expr::Ct { dreg: None, sreg: Some(NFT_REG_1), key: NFT_CT_SECMARK, dir: None, len: 4 },
    ];
    assert_eq!(run(&exprs, Some(&ct)), NFT_CONTINUE);
    assert_eq!(ct.secmark.get(), 9);
    assert_eq!(ct.events.get() & IPCT_SECMARK, IPCT_SECMARK);
}

#[test]
fn a_set_with_no_conntrack_is_a_silent_no_op_not_a_break() {
    // The reference does not refuse the packet when there is nothing to write
    // to; refusing would turn a marking rule into a filtering one.
    let exprs = vec![
        Expr::Immediate { dreg: NFT_REG_1, verdict: None, chain: None,
                          value: 1u32.to_ne_bytes().to_vec() },
        Expr::Ct { dreg: None, sreg: Some(NFT_REG_1), key: NFT_CT_MARK, dir: None, len: 4 },
    ];
    assert_eq!(run(&exprs, None), NFT_CONTINUE);
}

#[test]
fn an_expression_with_neither_register_breaks() {
    let exprs = vec![Expr::Ct { dreg: None, sreg: None, key: NFT_CT_MARK, dir: None, len: 4 }];
    let ct = Ct { ctinfo: IP_CT_ESTABLISHED, attached: true, ..Ct::default() };
    assert_eq!(run(&exprs, Some(&ct)), NFT_BREAK);
}
