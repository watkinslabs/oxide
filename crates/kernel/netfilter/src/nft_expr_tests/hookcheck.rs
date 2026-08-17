// Load-time refusal. An expression attached where it can never act is a rule
// the administrator believes is enforcing something and which does nothing;
// the refusal has to happen when the rule loads, not silently at run time.

extern crate alloc;
use alloc::string::String;
use alloc::vec;

use crate::nft_expr::expr::{Expr, ParseError};
use crate::nft_expr::flags::{NFTA_FIB_F_IIF, NFTA_FIB_F_OIF, NFTA_FIB_F_SADDR};
use crate::nft_expr::uapi::*;
use crate::nft_expr::validate::{validate_expr, validate_exprs};

const INET_HOOKS: [u8; 5] = [NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD,
                             NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING];

/// Assert an expression is accepted on exactly the listed hooks and refused
/// with `WrongHook` on every other inet hook.
fn only_on(expr: &Expr, family: u8, allowed: &[u8]) {
    for hook in INET_HOOKS {
        let got = validate_expr(expr, family, hook);
        if allowed.contains(&hook) {
            assert_eq!(got, Ok(()), "{expr:?} must be allowed on hook {hook}");
        } else {
            assert_eq!(got, Err(ParseError::WrongHook),
                "{expr:?} must be refused on hook {hook}");
        }
    }
}

fn nat(nat_type: u32) -> Expr {
    Expr::Nat { nat_type, family: NFPROTO_IPV4, flags: 0, sreg_addr_min: None,
                sreg_addr_max: None, sreg_proto_min: None, sreg_proto_max: None }
}

#[test]
fn source_translation_only_where_the_source_is_still_read() {
    only_on(&nat(NFT_NAT_SNAT), NFPROTO_IPV4, &[NF_INET_POST_ROUTING, NF_INET_LOCAL_IN]);
}

#[test]
fn destination_translation_only_where_the_destination_is_still_read() {
    only_on(&nat(NFT_NAT_DNAT), NFPROTO_IPV4, &[NF_INET_PRE_ROUTING, NF_INET_LOCAL_OUT]);
}

#[test]
fn an_unknown_translation_type_is_malformed_not_merely_misplaced() {
    assert_eq!(validate_expr(&nat(99), NFPROTO_IPV4, NF_INET_POST_ROUTING),
               Err(ParseError::Malformed));
}

#[test]
fn masquerade_only_after_routing_has_chosen_an_interface() {
    let e = Expr::Masq { flags: 0, sreg_proto_min: None, sreg_proto_max: None };
    only_on(&e, NFPROTO_IPV4, &[NF_INET_POST_ROUTING]);
}

#[test]
fn redirect_only_where_the_destination_can_still_be_moved() {
    let e = Expr::Redir { flags: 0, sreg_proto_min: None, sreg_proto_max: None };
    only_on(&e, NFPROTO_IPV4, &[NF_INET_PRE_ROUTING, NF_INET_LOCAL_OUT]);
}

#[test]
fn reject_is_refused_where_there_is_nobody_to_answer() {
    let e = Expr::Reject { reject_type: NFT_REJECT_TCP_RST, icmp_code: 0 };
    only_on(&e, NFPROTO_IPV4, &[NF_INET_LOCAL_IN, NF_INET_FORWARD, NF_INET_LOCAL_OUT,
                                NF_INET_PRE_ROUTING]);
    // The combined family additionally serves the earliest hook.
    assert_eq!(validate_expr(&e, NFPROTO_INET, NF_INET_INGRESS), Ok(()));
    assert_eq!(validate_expr(&e, NFPROTO_IPV4, NF_INET_INGRESS),
               Err(ParseError::WrongHook));
}

#[test]
fn a_queue_needs_a_family_with_somewhere_to_return_the_packet() {
    let e = Expr::Queue { num: 0, total: 1, flags: 0, sreg_qnum: None };
    for family in [NFPROTO_IPV4, NFPROTO_IPV6, NFPROTO_INET, NFPROTO_BRIDGE] {
        assert_eq!(validate_expr(&e, family, NF_INET_LOCAL_IN), Ok(()), "family {family}");
    }
    // A device chain has no continuation, so a queued packet could never come
    // back; accepting the rule would make it a silent drop.
    assert_eq!(validate_expr(&e, NFPROTO_NETDEV, NF_INET_LOCAL_IN),
               Err(ParseError::Unsupported));
}

#[test]
fn forwarding_belongs_to_a_device_chain_only() {
    let e = Expr::Fwd { sreg_dev: NFT_REG_1, sreg_addr: None, nfproto: None };
    assert_eq!(validate_expr(&e, NFPROTO_NETDEV, NF_NETDEV_INGRESS), Ok(()));
    assert_eq!(validate_expr(&e, NFPROTO_NETDEV, NF_NETDEV_EGRESS), Ok(()));
    assert_eq!(validate_expr(&e, NFPROTO_IPV4, NF_INET_FORWARD), Err(ParseError::Unsupported));
}

#[test]
fn offloading_belongs_to_the_forwarding_hook_only() {
    let e = Expr::FlowOffload { table: String::from("ft") };
    only_on(&e, NFPROTO_IPV4, &[NF_INET_FORWARD]);
    assert_eq!(validate_expr(&e, NFPROTO_NETDEV, NF_INET_FORWARD),
               Err(ParseError::Unsupported));
}

#[test]
fn the_path_size_key_is_bounded_to_hooks_that_have_a_path() {
    let mss = Expr::Rt { dreg: NFT_REG_1, key: NFT_RT_TCPMSS };
    only_on(&mss, NFPROTO_IPV4, &[NF_INET_FORWARD, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING]);
    // The other route keys are not hook-bound.
    for key in [NFT_RT_CLASSID, NFT_RT_NEXTHOP4, NFT_RT_NEXTHOP6, NFT_RT_XFRM] {
        for hook in INET_HOOKS {
            assert_eq!(validate_expr(&Expr::Rt { dreg: NFT_REG_1, key }, NFPROTO_IPV4, hook),
                       Ok(()), "key {key} hook {hook}");
        }
    }
    assert_eq!(validate_expr(&Expr::Rt { dreg: NFT_REG_1, key: 99 }, NFPROTO_IPV4,
                             NF_INET_LOCAL_IN), Err(ParseError::Malformed));
}

#[test]
fn socket_lookup_only_where_a_socket_can_be_found() {
    let e = Expr::Socket { dreg: NFT_REG_1, key: NFT_SOCKET_MARK, level: 0 };
    only_on(&e, NFPROTO_IPV4, &[NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_LOCAL_OUT]);
}

#[test]
fn transparent_proxying_only_before_routing() {
    let e = Expr::Tproxy { family: NFPROTO_IPV4, sreg_addr: None, sreg_port: None };
    only_on(&e, NFPROTO_IPV4, &[NF_INET_PRE_ROUTING]);
    assert_eq!(validate_expr(&e, NFPROTO_NETDEV, NF_INET_PRE_ROUTING),
               Err(ParseError::Unsupported));
}

#[test]
fn the_handshake_proxy_only_where_it_can_answer_for_the_host() {
    let e = Expr::Synproxy { mss: 1460, wscale: 7, flags: 0 };
    only_on(&e, NFPROTO_IPV4, &[NF_INET_LOCAL_IN, NF_INET_FORWARD]);
}

#[test]
fn a_transform_key_is_bounded_by_the_direction_it_reads() {
    let inbound = Expr::Xfrm { dreg: NFT_REG_1, key: NFT_XFRM_KEY_SPI,
                               dir: XFRM_POLICY_IN, spnum: 0 };
    only_on(&inbound, NFPROTO_IPV4, &[NF_INET_FORWARD, NF_INET_LOCAL_IN,
                                      NF_INET_PRE_ROUTING]);
    let outbound = Expr::Xfrm { dreg: NFT_REG_1, key: NFT_XFRM_KEY_SPI,
                                dir: XFRM_POLICY_OUT, spnum: 0 };
    only_on(&outbound, NFPROTO_IPV4, &[NF_INET_FORWARD, NF_INET_LOCAL_OUT,
                                       NF_INET_POST_ROUTING]);
    let bad = Expr::Xfrm { dreg: NFT_REG_1, key: NFT_XFRM_KEY_SPI, dir: 7, spnum: 0 };
    assert_eq!(validate_expr(&bad, NFPROTO_IPV4, NF_INET_FORWARD),
               Err(ParseError::Malformed));
}

#[test]
fn a_routing_lookup_is_bounded_by_what_it_asks_for() {
    let oif = Expr::Fib { dreg: NFT_REG_1, result: NFT_FIB_RESULT_OIF,
                          flags: NFTA_FIB_F_SADDR };
    only_on(&oif, NFPROTO_IPV4, &[NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD]);

    // An address-type lookup is allowed wherever the address it names exists.
    let by_iif = Expr::Fib { dreg: NFT_REG_1, result: NFT_FIB_RESULT_ADDRTYPE,
                             flags: NFTA_FIB_F_SADDR | NFTA_FIB_F_IIF };
    only_on(&by_iif, NFPROTO_IPV4, &[NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN,
                                     NF_INET_FORWARD]);
    let by_oif = Expr::Fib { dreg: NFT_REG_1, result: NFT_FIB_RESULT_ADDRTYPE,
                             flags: NFTA_FIB_F_SADDR | NFTA_FIB_F_OIF };
    only_on(&by_oif, NFPROTO_IPV4, &[NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING,
                                     NF_INET_FORWARD]);
    let anywhere = Expr::Fib { dreg: NFT_REG_1, result: NFT_FIB_RESULT_ADDRTYPE,
                               flags: NFTA_FIB_F_SADDR };
    only_on(&anywhere, NFPROTO_IPV4, &INET_HOOKS);
}

#[test]
fn the_expressions_with_no_hook_requirement_load_anywhere() {
    let free = [
        Expr::Counter,
        Expr::Cmp { sreg: NFT_REG_1, op: NFT_CMP_EQ, data: alloc::vec![1] },
        Expr::Meta { dreg: Some(NFT_REG_1), sreg: None, key: NFT_META_LEN },
        Expr::Ct { dreg: Some(NFT_REG_1), sreg: None, key: NFT_CT_STATE, dir: None, len: 4 },
        Expr::Limit { index: 0, limit_type: NFT_LIMIT_PKTS, rate: 1, nsecs: 1,
                      burst: 1, tokens_max: 1, invert: false },
        Expr::Log { group: None, prefix: String::new(), snaplen: 0, qthreshold: 0,
                    level: 4, flags: 0 },
    ];
    for e in &free {
        for hook in INET_HOOKS {
            assert_eq!(validate_expr(e, NFPROTO_IPV4, hook), Ok(()), "{e:?} on hook {hook}");
        }
    }
}

#[test]
fn one_bad_expression_refuses_the_whole_rule() {
    // A rule that loaded with its translation silently dropped would filter
    // nothing and translate nothing, while reading as installed.
    let exprs = vec![
        Expr::Counter,
        nat(NFT_NAT_SNAT),
        Expr::Immediate { dreg: NFT_REG_VERDICT, verdict: Some(NF_ACCEPT), chain: None,
                          value: alloc::vec::Vec::new() },
    ];
    assert_eq!(validate_exprs(&exprs, NFPROTO_IPV4, NF_INET_PRE_ROUTING),
               Err(ParseError::WrongHook));
    assert_eq!(validate_exprs(&exprs, NFPROTO_IPV4, NF_INET_POST_ROUTING), Ok(()));
}

#[test]
fn a_hook_number_outside_the_mask_width_is_refused_not_wrapped() {
    // A shift by more than the mask width is undefined territory; the check
    // must refuse rather than alias onto a legal hook.
    let e = Expr::Masq { flags: 0, sreg_proto_min: None, sreg_proto_max: None };
    assert_eq!(validate_expr(&e, NFPROTO_IPV4, 32), Err(ParseError::WrongHook));
    assert_eq!(validate_expr(&e, NFPROTO_IPV4, 255), Err(ParseError::WrongHook));
}
