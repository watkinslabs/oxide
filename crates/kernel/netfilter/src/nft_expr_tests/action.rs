// Expressions that act on the packet. Each records an effect rather than
// performing one, so the assertion is on the recorded effect: a translation
// onto the wrong address, or a reject that does not drop, is the failure mode.

extern crate alloc;
use alloc::vec;

use conntrack::tuple::InetAddr;
use nat::uapi::{NF_NAT_MANIP_DST, NF_NAT_MANIP_SRC, NF_NAT_RANGE_MAP_IPS,
                NF_NAT_RANGE_NETMAP, NF_NAT_RANGE_PROTO_SPECIFIED,
                NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING, NF_INET_PRE_ROUTING};

use crate::nft_expr::action::Action;
use crate::nft_expr::ctx::EvalCtx;
use crate::nft_expr::expr::Expr;
use crate::nft_expr::flags::{NFT_QUEUE_FLAG_BYPASS, NFT_QUEUE_FLAG_CPU_FANOUT};
use crate::nft_expr::limits::{ETH_P_IP, ETH_P_IPV6};
use crate::nft_expr::run::action::icmpx_code;
use crate::nft_expr::run::run_rule_ctx;
use crate::nft_expr::stateful::ExprStates;
use crate::nft_expr::uapi::*;
use super::fixture::{self, Ct, Cookies, Route, Sock};

fn imm(reg: u32, bytes: &[u8]) -> Expr {
    Expr::Immediate { dreg: reg, verdict: None, chain: None, value: bytes.to_vec() }
}

struct Run { code: i32, actions: alloc::vec::Vec<Action> }

/// Per-expression state outlives the context that borrows it. A test builds a
/// fresh set per run and never reclaims it: the process is a test binary, and
/// tying the state's lifetime to the caller's frame would put an extra
/// binding at every call site for no assertion value.
fn leak_states(exprs: &[Expr]) -> &'static ExprStates {
    alloc::boxed::Box::leak(alloc::boxed::Box::new(ExprStates::for_exprs(exprs)))
}

fn run_on<'a>(exprs: &[Expr], pkt: &'a [u8], setup: impl FnOnce(&mut EvalCtx<'a>)) -> Run {
    let mut ctx = EvalCtx::ipv4(pkt, leak_states(exprs));
    setup(&mut ctx);
    let v = run_rule_ctx(exprs, &mut ctx);
    Run { code: v.code, actions: ctx.actions }
}

fn tcp_pkt() -> alloc::vec::Vec<u8> {
    fixture::ipv4(6, [10, 0, 0, 1], [93, 184, 216, 34], &fixture::tcp(1234, 80, 0x02, &[]))
}

#[test]
fn a_source_translation_records_the_address_from_its_register() {
    let exprs = vec![
        imm(NFT_REG_1, &[203, 0, 113, 5]),
        Expr::Nat { nat_type: NFT_NAT_SNAT, family: NFPROTO_IPV4,
                    flags: NF_NAT_RANGE_MAP_IPS, sreg_addr_min: Some(NFT_REG_1),
                    sreg_addr_max: None, sreg_proto_min: None, sreg_proto_max: None },
    ];
    let r = run_on(&exprs, &tcp_pkt(), |_| {});
    assert_eq!(r.code, NFT_CONTINUE, "a binding request does not decide the packet");
    match &r.actions[..] {
        [Action::Nat { manip, range }] => {
            assert_eq!(*manip, NF_NAT_MANIP_SRC);
            assert_eq!(&range.min_addr.0[..4], &[203, 0, 113, 5]);
            assert_eq!(range.min_addr, range.max_addr, "one register means one address");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_destination_translation_selects_the_other_manipulation() {
    let exprs = vec![
        imm(NFT_REG_1, &[10, 0, 0, 50]),
        Expr::Nat { nat_type: NFT_NAT_DNAT, family: NFPROTO_IPV4,
                    flags: NF_NAT_RANGE_MAP_IPS, sreg_addr_min: Some(NFT_REG_1),
                    sreg_addr_max: None, sreg_proto_min: None, sreg_proto_max: None },
    ];
    let r = run_on(&exprs, &tcp_pkt(), |_| {});
    // Choosing the wrong manipulation rewrites the wrong end and sends the
    // flow somewhere nobody asked for.
    assert!(matches!(&r.actions[..], [Action::Nat { manip, .. }] if *manip == NF_NAT_MANIP_DST));
}

#[test]
fn a_translation_range_spans_both_registers() {
    let exprs = vec![
        imm(NFT_REG_1, &[203, 0, 113, 10]),
        imm(NFT_REG_2, &[203, 0, 113, 20]),
        imm(NFT_REG_3, &2000u16.to_be_bytes()),
        imm(NFT_REG_4, &2100u16.to_be_bytes()),
        Expr::Nat { nat_type: NFT_NAT_SNAT, family: NFPROTO_IPV4,
                    flags: NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED,
                    sreg_addr_min: Some(NFT_REG_1), sreg_addr_max: Some(NFT_REG_2),
                    sreg_proto_min: Some(NFT_REG_3), sreg_proto_max: Some(NFT_REG_4) },
    ];
    let r = run_on(&exprs, &tcp_pkt(), |_| {});
    match &r.actions[..] {
        [Action::Nat { range, .. }] => {
            assert_eq!(&range.min_addr.0[..4], &[203, 0, 113, 10]);
            assert_eq!(&range.max_addr.0[..4], &[203, 0, 113, 20]);
            assert_eq!((range.min_proto, range.max_proto), (2000, 2100));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_prefix_translation_keeps_the_host_part() {
    // Mapping 10.0.0.0/24 onto 192.0.2.0/24 must send .1 to .1, not collapse
    // every host onto the network address.
    let exprs = vec![
        imm(NFT_REG_1, &[192, 0, 2, 0]),
        imm(NFT_REG_2, &[192, 0, 2, 255]),
        Expr::Nat { nat_type: NFT_NAT_SNAT, family: NFPROTO_IPV4,
                    flags: NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_NETMAP,
                    sreg_addr_min: Some(NFT_REG_1), sreg_addr_max: Some(NFT_REG_2),
                    sreg_proto_min: None, sreg_proto_max: None },
    ];
    let r = run_on(&exprs, &tcp_pkt(), |_| {});
    match &r.actions[..] {
        [Action::Nat { range, .. }] => assert_eq!(&range.min_addr.0[..4], &[192, 0, 2, 1]),
        other => panic!("{other:?}"),
    }
}

#[test]
fn masquerade_takes_the_egress_address_and_drops_without_one() {
    let exprs = vec![Expr::Masq { flags: 0, sreg_proto_min: None, sreg_proto_max: None }];
    let route = Route { src_addr: Some(InetAddr::v4([203, 0, 113, 5])), ..Route::default() };
    let r = run_on(&exprs, &tcp_pkt(), |c| { c.hook = NF_INET_POST_ROUTING; c.route = Some(&route); });
    match &r.actions[..] {
        [Action::Masquerade { range }] =>
            assert_eq!(&range.min_addr.0[..4], &[203, 0, 113, 5]),
        other => panic!("{other:?}"),
    }
    // With no address there is nothing valid to translate onto. Passing the
    // packet through untranslated would leak the private source onto the wire.
    let none = Route::default();
    let r = run_on(&exprs, &tcp_pkt(), |c| { c.hook = NF_INET_POST_ROUTING; c.route = Some(&none); });
    assert_eq!(r.code, NF_DROP);
    assert!(r.actions.is_empty());
}

#[test]
fn masquerade_at_a_hook_that_cannot_serve_it_drops() {
    let exprs = vec![Expr::Masq { flags: 0, sreg_proto_min: None, sreg_proto_max: None }];
    let route = Route { src_addr: Some(InetAddr::v4([203, 0, 113, 5])), ..Route::default() };
    let r = run_on(&exprs, &tcp_pkt(), |c| { c.hook = NF_INET_PRE_ROUTING; c.route = Some(&route); });
    assert_eq!(r.code, NF_DROP, "the egress interface is not known yet");
}

#[test]
fn redirect_targets_loopback_on_output_and_the_interface_on_input() {
    let exprs = vec![Expr::Redir { flags: 0, sreg_proto_min: None, sreg_proto_max: None }];
    let r = run_on(&exprs, &tcp_pkt(), |c| c.hook = NF_INET_LOCAL_OUT);
    match &r.actions[..] {
        [Action::Redirect { range }] => assert_eq!(&range.min_addr.0[..4], &[127, 0, 0, 1]),
        other => panic!("{other:?}"),
    }
    let route = Route { iface_addr: Some(InetAddr::v4([192, 168, 1, 1])), ..Route::default() };
    let r = run_on(&exprs, &tcp_pkt(), |c| { c.hook = NF_INET_PRE_ROUTING; c.route = Some(&route); });
    match &r.actions[..] {
        [Action::Redirect { range }] => assert_eq!(&range.min_addr.0[..4], &[192, 168, 1, 1]),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_redirect_port_comes_from_its_register() {
    let exprs = vec![
        imm(NFT_REG_1, &3128u16.to_be_bytes()),
        Expr::Redir { flags: NF_NAT_RANGE_PROTO_SPECIFIED, sreg_proto_min: Some(NFT_REG_1),
                      sreg_proto_max: None },
    ];
    let r = run_on(&exprs, &tcp_pkt(), |c| c.hook = NF_INET_LOCAL_OUT);
    match &r.actions[..] {
        [Action::Redirect { range }] => {
            assert_eq!((range.min_proto, range.max_proto), (3128, 3128));
            assert_eq!(range.flags & NF_NAT_RANGE_PROTO_SPECIFIED, NF_NAT_RANGE_PROTO_SPECIFIED);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_reject_always_drops() {
    // A reject that recorded its answer but let the packet continue would be
    // an accept with extra steps.
    for (kind, code) in [(NFT_REJECT_ICMP_UNREACH, 3u8), (NFT_REJECT_TCP_RST, 0),
                         (NFT_REJECT_ICMPX_UNREACH, 1)]
    {
        let exprs = vec![Expr::Reject { reject_type: kind, icmp_code: code }];
        let r = run_on(&exprs, &tcp_pkt(), |_| {});
        assert_eq!(r.code, NF_DROP, "reject type {kind}");
        assert!(matches!(&r.actions[..], [Action::Reject { .. }]));
    }
}

#[test]
fn a_reject_records_the_family_it_must_answer_in() {
    let exprs = vec![Expr::Reject { reject_type: NFT_REJECT_ICMPX_UNREACH, icmp_code: 1 }];
    let states = ExprStates::for_exprs(&exprs);
    let pkt = tcp_pkt();
    let mut ctx = EvalCtx::new(&pkt, NFPROTO_IPV6, &states);
    run_rule_ctx(&exprs, &mut ctx);
    assert!(matches!(&ctx.actions[..], [Action::Reject { family, .. }] if *family == NFPROTO_IPV6));
}

#[test]
fn the_portable_reject_codes_map_onto_each_family() {
    use crate::nft_expr::limits::*;
    let cases = [
        (NFT_REJECT_ICMPX_NO_ROUTE, ICMP_NET_UNREACH, ICMPV6_NOROUTE),
        (NFT_REJECT_ICMPX_PORT_UNREACH, ICMP_PORT_UNREACH, ICMPV6_PORT_UNREACH),
        (NFT_REJECT_ICMPX_HOST_UNREACH, ICMP_HOST_UNREACH, ICMPV6_ADDR_UNREACH),
        (NFT_REJECT_ICMPX_ADMIN_PROHIBITED, ICMP_PKT_FILTERED, ICMPV6_ADM_PROHIBITED),
    ];
    for (code, v4, v6) in cases {
        assert_eq!(icmpx_code(NFPROTO_IPV4, code), v4, "code {code} on v4");
        assert_eq!(icmpx_code(NFPROTO_IPV6, code), v6, "code {code} on v6");
    }
}

#[test]
fn a_queue_verdict_carries_its_queue_number() {
    let exprs = vec![Expr::Queue { num: 7, total: 1, flags: 0, sreg_qnum: None }];
    let r = run_on(&exprs, &tcp_pkt(), |_| {});
    assert_eq!(r.code & NF_VERDICT_MASK, NF_QUEUE);
    assert_eq!((r.code >> 16) as u16, 7);
}

#[test]
fn the_bypass_flag_rides_the_verdict() {
    // Without the flag a queue with no reader drops the packet; with it the
    // packet continues. Losing the flag turns an accept into a silent drop.
    let plain = vec![Expr::Queue { num: 1, total: 1, flags: 0, sreg_qnum: None }];
    let bypass = vec![Expr::Queue { num: 1, total: 1, flags: NFT_QUEUE_FLAG_BYPASS,
                                    sreg_qnum: None }];
    assert_eq!(run_on(&plain, &tcp_pkt(), |_| {}).code & NF_VERDICT_FLAG_QUEUE_BYPASS, 0);
    assert_ne!(run_on(&bypass, &tcp_pkt(), |_| {}).code & NF_VERDICT_FLAG_QUEUE_BYPASS, 0);
}

#[test]
fn a_queue_range_keeps_one_flow_on_one_reader() {
    // Both directions of a conversation must reach the same reader, or a
    // stateful userspace filter sees half a flow.
    let exprs = vec![Expr::Queue { num: 10, total: 4, flags: 0, sreg_qnum: None }];
    let a = run_on(&exprs, &tcp_pkt(), |_| {}).code;
    let b = run_on(&exprs, &tcp_pkt(), |_| {}).code;
    assert_eq!(a, b, "the same flow must land in the same queue every time");
    let q = (a >> 16) as u16;
    assert!((10..14).contains(&q), "queue {q} is outside the range");
}

#[test]
fn processor_fanout_selects_by_processor() {
    let exprs = vec![Expr::Queue { num: 0, total: 4, flags: NFT_QUEUE_FLAG_CPU_FANOUT,
                                   sreg_qnum: None }];
    for cpu in 0..8u32 {
        let r = run_on(&exprs, &tcp_pkt(), |c| c.cpu = cpu);
        assert_eq!((r.code >> 16) as u16, (cpu % 4) as u16);
    }
}

#[test]
fn a_register_supplied_queue_number_is_used_verbatim() {
    let exprs = vec![
        imm(NFT_REG_1, &99u32.to_ne_bytes()),
        Expr::Queue { num: 0, total: 0, flags: 0, sreg_qnum: Some(NFT_REG_1) },
    ];
    assert_eq!((run_on(&exprs, &tcp_pkt(), |_| {}).code >> 16) as u16, 99);
}

#[test]
fn forwarding_steals_the_packet_and_refuses_an_exhausted_hop_limit() {
    let exprs = vec![
        imm(NFT_REG_1, &3u32.to_ne_bytes()),
        Expr::Fwd { sreg_dev: NFT_REG_1, sreg_addr: None, nfproto: None },
    ];
    let r = run_on(&exprs, &tcp_pkt(), |_| {});
    assert_eq!(r.code, NF_STOLEN, "the packet has left; nothing else may act on it");
    assert!(matches!(&r.actions[..], [Action::Fwd { oif: 3, nfproto: None, gateway: None }]));

    // The neighbour form forwards, so a packet that may not be forwarded again
    // has to be refused rather than looped.
    let neigh = vec![
        imm(NFT_REG_1, &3u32.to_ne_bytes()),
        Expr::Fwd { sreg_dev: NFT_REG_1, sreg_addr: None, nfproto: Some(NFPROTO_IPV4) },
    ];
    let mut dead = tcp_pkt();
    dead[8] = 1;
    let r = run_on(&neigh, &dead, |c| c.meta.protocol = Some(ETH_P_IP));
    assert_eq!(r.code, NF_DROP);
    let live = tcp_pkt();
    let r = run_on(&neigh, &live, |c| c.meta.protocol = Some(ETH_P_IP));
    assert_eq!(r.code, NF_STOLEN);
}

#[test]
fn the_neighbour_form_refuses_a_packet_of_the_wrong_family() {
    let exprs = vec![
        imm(NFT_REG_1, &3u32.to_ne_bytes()),
        Expr::Fwd { sreg_dev: NFT_REG_1, sreg_addr: None, nfproto: Some(NFPROTO_IPV6) },
    ];
    let r = run_on(&exprs, &tcp_pkt(), |c| c.meta.protocol = Some(ETH_P_IP));
    assert_eq!(r.code, NFT_BREAK);
    assert!(r.actions.is_empty(), "nothing may be sent on a mismatch");
    let _ = ETH_P_IPV6;
}

#[test]
fn a_duplicate_leaves_the_originals_verdict_alone() {
    let exprs = vec![
        imm(NFT_REG_1, &5u32.to_ne_bytes()),
        Expr::Dup { sreg_addr: None, sreg_dev: Some(NFT_REG_1) },
    ];
    let r = run_on(&exprs, &tcp_pkt(), |_| {});
    assert_eq!(r.code, NFT_CONTINUE);
    assert!(matches!(&r.actions[..], [Action::Dup { oif: Some(5), gateway: None }]));
}

#[test]
fn a_log_records_and_decides_nothing() {
    let exprs = vec![Expr::Log { group: None, prefix: alloc::string::String::from("drop: "),
                                 snaplen: 0, qthreshold: 0, level: 4, flags: 0 }];
    let r = run_on(&exprs, &tcp_pkt(), |_| {});
    assert_eq!(r.code, NFT_CONTINUE);
    assert!(matches!(&r.actions[..], [Action::Log { level: 4, .. }]));
}

#[test]
fn transparent_proxying_needs_a_transparent_socket() {
    let exprs = vec![Expr::Tproxy { family: NFPROTO_UNSPEC, sreg_addr: None,
                                    sreg_port: None }];
    let ok = Sock { present: true, full: true, tproxy_ok: true, ..Sock::default() };
    let r = run_on(&exprs, &tcp_pkt(), |c| c.socket = Some(&ok));
    assert_eq!(r.code, NFT_CONTINUE);
    assert!(matches!(&r.actions[..], [Action::TproxyAssign { port: 80, .. }]));

    // Handing a packet to a socket that did not ask for foreign addresses
    // would deliver another host's traffic to it.
    let no = Sock { present: true, full: true, tproxy_ok: false, ..Sock::default() };
    let r = run_on(&exprs, &tcp_pkt(), |c| c.socket = Some(&no));
    assert_eq!(r.code, NFT_BREAK);
    assert!(r.actions.is_empty());
}

#[test]
fn transparent_proxying_refuses_a_protocol_it_cannot_redirect() {
    let icmp = fixture::ipv4(1, [10, 0, 0, 1], [10, 0, 0, 2], &[8, 0, 0, 0, 0, 0, 0, 0]);
    let exprs = vec![Expr::Tproxy { family: NFPROTO_UNSPEC, sreg_addr: None,
                                    sreg_port: None }];
    let ok = Sock { present: true, full: true, tproxy_ok: true, ..Sock::default() };
    let r = run_on(&exprs, &icmp, |c| { c.meta.l4proto = Some(1); c.socket = Some(&ok); });
    assert_eq!(r.code, NFT_BREAK);
}

#[test]
fn the_handshake_proxy_consumes_an_opening_segment() {
    let exprs = vec![Expr::Synproxy { mss: 1460, wscale: 7, flags: 0 }];
    let syn = fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &fixture::tcp(1234, 80, 0x02, &[]));
    let r = run_on(&exprs, &syn, |c| c.meta.l4proto = Some(6));
    assert_eq!(r.code, NF_STOLEN, "the proxy answers it, so nothing downstream sees it");
    assert!(matches!(&r.actions[..], [Action::Synproxy { mss: 1460, wscale: 7, .. }]));
}

#[test]
fn the_handshake_proxy_drops_an_acknowledgement_with_no_valid_cookie() {
    // This is the whole defence: an acknowledgement nobody's cookie authorises
    // must not be forwarded to the protected host.
    let ack = fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &fixture::tcp(1234, 80, 0x10, &[]));
    let exprs = vec![Expr::Synproxy { mss: 1460, wscale: 7, flags: 0 }];
    let bad = Cookies { valid: false };
    let r = run_on(&exprs, &ack, |c| { c.meta.l4proto = Some(6); c.synproxy = Some(&bad); });
    assert_eq!(r.code, NF_DROP);
    let good = Cookies { valid: true };
    let r = run_on(&exprs, &ack, |c| { c.meta.l4proto = Some(6); c.synproxy = Some(&good); });
    assert_eq!(r.code, NF_STOLEN);
}

#[test]
fn the_handshake_proxy_needs_a_cookie_source() {
    let ack = fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &fixture::tcp(1234, 80, 0x10, &[]));
    let exprs = vec![Expr::Synproxy { mss: 1460, wscale: 7, flags: 0 }];
    let r = run_on(&exprs, &ack, |c| c.meta.l4proto = Some(6));
    assert_eq!(r.code, NFT_BREAK, "with no cookie machinery nothing may be validated");
}

#[test]
fn offloading_needs_a_flow_that_may_be_offloaded() {
    let exprs = vec![Expr::FlowOffload { table: alloc::string::String::from("ft") }];
    let ready = Ct { attached: true, offloadable: true, ..Ct::default() };
    let r = run_on(&exprs, &tcp_pkt(), |c| {
        c.ct = Some(&ready); c.table = Some("filter");
    });
    assert_eq!(r.code, NFT_CONTINUE);
    assert!(matches!(&r.actions[..], [Action::FlowOffload { table, flowtable }]
        if table == "filter" && flowtable == "ft"));
    // A flow the software path must keep seeing — a helper, an unconfirmed
    // entry — must not be handed to a table that bypasses the rules.
    let not = Ct { attached: true, offloadable: false, ..Ct::default() };
    let r = run_on(&exprs, &tcp_pkt(), |c| c.ct = Some(&not));
    assert_eq!(r.code, NFT_BREAK);
    assert!(r.actions.is_empty());
}
