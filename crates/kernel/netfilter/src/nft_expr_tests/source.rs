// Expressions that read a source outside the packet, plus the header-option
// walkers. The shared failure mode is fabricating a value when the source is
// absent: a rule testing "no route" must not be satisfied by a zero.

extern crate alloc;
use alloc::vec;

use conntrack::tuple::InetAddr;

use crate::nft_expr::access::{FibEntry, XfrmState};
use crate::nft_expr::action::Action;
use crate::nft_expr::ctx::EvalCtx;
use crate::nft_expr::expr::Expr;
use crate::nft_expr::flags::*;
use crate::nft_expr::limits::IFNAMSIZ;
use crate::nft_expr::run::run_rule_ctx;
use crate::nft_expr::run::source::{find_ipv4_option, find_ipv6_exthdr, find_sctp_chunk,
                                   find_tcp_option, tcp_optlen};
use crate::nft_expr::stateful::ExprStates;
use crate::nft_expr::uapi::*;
use super::fixture::{self, Osf, Route, Sock, Tunnel, Xfrm};

fn drop_now() -> Expr {
    Expr::Immediate { dreg: NFT_REG_VERDICT, verdict: Some(NF_DROP), chain: None,
                      value: alloc::vec::Vec::new() }
}

/// Per-expression state outlives the context that borrows it. A test builds a
/// fresh set per run and never reclaims it: the process is a test binary, and
/// tying the state's lifetime to the caller's frame would put an extra
/// binding at every call site for no assertion value.
fn leak_states(exprs: &[Expr]) -> &'static ExprStates {
    alloc::boxed::Box::leak(alloc::boxed::Box::new(ExprStates::for_exprs(exprs)))
}

fn run<'a>(exprs: &[Expr], pkt: &'a [u8], setup: impl FnOnce(&mut EvalCtx<'a>)) -> i32 {
    let mut ctx = EvalCtx::ipv4(pkt, leak_states(exprs));
    setup(&mut ctx);
    run_rule_ctx(exprs, &mut ctx).code
}

fn match_key(expr: Expr, want: &[u8]) -> alloc::vec::Vec<Expr> {
    vec![expr, Expr::Cmp { sreg: NFT_REG_1, op: NFT_CMP_EQ, data: want.to_vec() }, drop_now()]
}

fn tcp_pkt(control: u8, options: &[u8]) -> alloc::vec::Vec<u8> {
    fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &fixture::tcp(1234, 80, control, options))
}

// --- route ---

#[test]
fn route_keys_report_what_the_route_holds() {
    let route = Route { classid: Some(0x10), nexthop4: Some([192, 168, 1, 254]),
                        tcpmss: Some(1400), transformed: true, ..Route::default() };
    let cases: [(u32, alloc::vec::Vec<u8>); 4] = [
        (NFT_RT_CLASSID, 0x10u32.to_ne_bytes().to_vec()),
        (NFT_RT_NEXTHOP4, alloc::vec![192, 168, 1, 254]),
        (NFT_RT_TCPMSS, 1400u16.to_ne_bytes().to_vec()),
        (NFT_RT_XFRM, alloc::vec![1]),
    ];
    for (key, want) in cases {
        let exprs = match_key(Expr::Rt { dreg: NFT_REG_1, key }, &want);
        assert_eq!(run(&exprs, &tcp_pkt(0x10, &[]), |c| c.route = Some(&route)), NF_DROP,
            "route key {key}");
    }
}

#[test]
fn a_route_key_with_no_route_breaks() {
    let exprs = match_key(Expr::Rt { dreg: NFT_REG_1, key: NFT_RT_CLASSID },
                          &0u32.to_ne_bytes());
    assert_eq!(run(&exprs, &tcp_pkt(0x10, &[]), |_| {}), NFT_BREAK);
    // Present but with nothing to report is equally not a zero.
    let empty = Route::default();
    assert_eq!(run(&exprs, &tcp_pkt(0x10, &[]), |c| c.route = Some(&empty)), NFT_BREAK);
}

#[test]
fn a_next_hop_key_refuses_the_other_family() {
    let route = Route { nexthop4: Some([1, 2, 3, 4]), nexthop6: Some([0xff; 16]),
                        ..Route::default() };
    let v6 = match_key(Expr::Rt { dreg: NFT_REG_1, key: NFT_RT_NEXTHOP6 }, &[0xff; 16]);
    assert_eq!(run(&v6, &tcp_pkt(0x10, &[]), |c| c.route = Some(&route)), NFT_BREAK,
        "an IPv4 packet has no IPv6 next hop");
}

// --- routing table ---

fn fib_entry(oif: Option<u32>, name: &[u8], addrtype: u32) -> FibEntry {
    let mut oifname = [0u8; IFNAMSIZ];
    oifname[..name.len()].copy_from_slice(name);
    FibEntry { oif, oifname, addrtype }
}

#[test]
fn a_routing_lookup_reports_the_interface_and_its_name() {
    let route = Route { fib: Some(fib_entry(Some(3), b"eth0", 1)), ..Route::default() };
    let by_index = match_key(
        Expr::Fib { dreg: NFT_REG_1, result: NFT_FIB_RESULT_OIF, flags: NFTA_FIB_F_SADDR },
        &3u32.to_ne_bytes());
    assert_eq!(run(&by_index, &tcp_pkt(0x10, &[]), |c| c.route = Some(&route)), NF_DROP);
    let mut want = [0u8; IFNAMSIZ];
    want[..4].copy_from_slice(b"eth0");
    let by_name = match_key(
        Expr::Fib { dreg: NFT_REG_1, result: NFT_FIB_RESULT_OIFNAME, flags: NFTA_FIB_F_SADDR },
        &want);
    assert_eq!(run(&by_name, &tcp_pkt(0x10, &[]), |c| c.route = Some(&route)), NF_DROP);
}

#[test]
fn a_locally_delivered_route_reports_no_interface() {
    // This is how a reverse-path rule tells "arrived for us" from "arrived on
    // the interface we would route back through". Reporting zero would make
    // every local packet look like it belongs to interface zero.
    let local = Route { fib: Some(fib_entry(None, b"", 2)), ..Route::default() };
    let exprs = match_key(
        Expr::Fib { dreg: NFT_REG_1, result: NFT_FIB_RESULT_OIF, flags: NFTA_FIB_F_SADDR },
        &0u32.to_ne_bytes());
    assert_eq!(run(&exprs, &tcp_pkt(0x10, &[]), |c| c.route = Some(&local)), NFT_BREAK);
    // Its address type still answers.
    let addrtype = match_key(
        Expr::Fib { dreg: NFT_REG_1, result: NFT_FIB_RESULT_ADDRTYPE, flags: NFTA_FIB_F_SADDR },
        &2u32.to_ne_bytes());
    assert_eq!(run(&addrtype, &tcp_pkt(0x10, &[]), |c| c.route = Some(&local)), NF_DROP);
}

#[test]
fn the_presence_flag_answers_with_a_boolean_instead_of_breaking() {
    let none = Route { fib: None, ..Route::default() };
    let exprs = match_key(
        Expr::Fib { dreg: NFT_REG_1, result: NFT_FIB_RESULT_OIF,
                    flags: NFTA_FIB_F_SADDR | NFTA_FIB_F_PRESENT },
        &[0]);
    assert_eq!(run(&exprs, &tcp_pkt(0x10, &[]), |c| c.route = Some(&none)), NF_DROP,
        "no route present reads as false, which is a matchable answer");
    let some = Route { fib: Some(fib_entry(Some(1), b"eth0", 1)), ..Route::default() };
    let yes = match_key(
        Expr::Fib { dreg: NFT_REG_1, result: NFT_FIB_RESULT_OIF,
                    flags: NFTA_FIB_F_SADDR | NFTA_FIB_F_PRESENT },
        &[1]);
    assert_eq!(run(&yes, &tcp_pkt(0x10, &[]), |c| c.route = Some(&some)), NF_DROP);
}

#[test]
fn the_lookup_key_selects_the_address_the_flags_name() {
    use crate::nft_expr::run::source::fib_addr;
    let pkt = tcp_pkt(0x10, &[]);
    let states = ExprStates::empty();
    let ctx = EvalCtx::ipv4(&pkt, &states);
    assert_eq!(fib_addr(&ctx, NFTA_FIB_F_SADDR), Some(InetAddr::v4([10, 0, 0, 1])));
    assert_eq!(fib_addr(&ctx, NFTA_FIB_F_DADDR), Some(InetAddr::v4([10, 0, 0, 2])));
}

// --- socket ---

#[test]
fn socket_keys_report_the_owning_socket() {
    let sock = Sock { present: true, full: true, transparent: true, mark: 0x77,
                      wildcard: true, cgroup: Some(9), tproxy_ok: false };
    for (key, want) in [(NFT_SOCKET_TRANSPARENT, alloc::vec![1u8]),
                        (NFT_SOCKET_MARK, 0x77u32.to_ne_bytes().to_vec()),
                        (NFT_SOCKET_WILDCARD, alloc::vec![1u8]),
                        (NFT_SOCKET_CGROUPV2, 9u64.to_ne_bytes().to_vec())]
    {
        let exprs = match_key(Expr::Socket { dreg: NFT_REG_1, key, level: 0 }, &want);
        assert_eq!(run(&exprs, &tcp_pkt(0x10, &[]), |c| c.socket = Some(&sock)), NF_DROP,
            "socket key {key}");
    }
}

#[test]
fn a_socket_key_with_no_socket_breaks() {
    let exprs = match_key(Expr::Socket { dreg: NFT_REG_1, key: NFT_SOCKET_MARK, level: 0 },
                          &0u32.to_ne_bytes());
    assert_eq!(run(&exprs, &tcp_pkt(0x10, &[]), |_| {}), NFT_BREAK);
    let absent = Sock { present: false, ..Sock::default() };
    assert_eq!(run(&exprs, &tcp_pkt(0x10, &[]), |c| c.socket = Some(&absent)), NFT_BREAK);
}

#[test]
fn a_stub_socket_has_no_mark_of_its_own() {
    // A request or time-wait stub is not a socket a mark can belong to;
    // reporting zero would match a rule looking for an unmarked socket.
    let stub = Sock { present: true, full: false, ..Sock::default() };
    let exprs = match_key(Expr::Socket { dreg: NFT_REG_1, key: NFT_SOCKET_MARK, level: 0 },
                          &0u32.to_ne_bytes());
    assert_eq!(run(&exprs, &tcp_pkt(0x10, &[]), |c| c.socket = Some(&stub)), NFT_BREAK);
    let wildcard = match_key(Expr::Socket { dreg: NFT_REG_1, key: NFT_SOCKET_WILDCARD,
                                            level: 0 }, &[0]);
    assert_eq!(run(&wildcard, &tcp_pkt(0x10, &[]), |c| c.socket = Some(&stub)), NFT_BREAK);
    // Transparency is a property of the stub too, so it still answers.
    let transparent = match_key(Expr::Socket { dreg: NFT_REG_1,
                                               key: NFT_SOCKET_TRANSPARENT, level: 0 }, &[0]);
    assert_eq!(run(&transparent, &tcp_pkt(0x10, &[]), |c| c.socket = Some(&stub)), NF_DROP);
}

// --- fingerprint, transform, tunnel ---

#[test]
fn a_fingerprint_is_only_taken_from_an_opening_segment() {
    let prints = Osf { genre: b"Linux" };
    let mut want = [0u8; crate::nft_expr::limits::NFT_OSF_MAXGENRELEN];
    want[..5].copy_from_slice(b"Linux");
    let exprs = match_key(Expr::Osf { dreg: NFT_REG_1, ttl: 0, flags: 0 }, &want);
    assert_eq!(run(&exprs, &tcp_pkt(0x02, &[]), |c| {
        c.meta.l4proto = Some(6); c.osf = Some(&prints);
    }), NF_DROP);
    // Anything mid-flow carries no fingerprint.
    for control in [0x10u8, 0x12, 0x11, 0x04] {
        assert_eq!(run(&exprs, &tcp_pkt(control, &[]), |c| {
            c.meta.l4proto = Some(6); c.osf = Some(&prints);
        }), NFT_BREAK, "control {control:#x}");
    }
}

#[test]
fn an_unmatched_fingerprint_reports_unknown() {
    let mut want = [0u8; crate::nft_expr::limits::NFT_OSF_MAXGENRELEN];
    want[..7].copy_from_slice(b"unknown");
    let exprs = match_key(Expr::Osf { dreg: NFT_REG_1, ttl: 0, flags: 0 }, &want);
    assert_eq!(run(&exprs, &tcp_pkt(0x02, &[]), |c| c.meta.l4proto = Some(6)), NF_DROP);
}

#[test]
fn transform_keys_report_the_state_at_their_index() {
    let state = XfrmState { family: NFPROTO_IPV4, saddr: [0u8; 16], daddr: [0u8; 16],
                            reqid: 5, spi: 0x1000, tunnel_mode: false };
    let xfrm = Xfrm { state: Some(state) };
    for (key, want) in [(NFT_XFRM_KEY_REQID, 5u32.to_ne_bytes()),
                        (NFT_XFRM_KEY_SPI, 0x1000u32.to_ne_bytes())]
    {
        let exprs = match_key(Expr::Xfrm { dreg: NFT_REG_1, key, dir: 0, spnum: 0 }, &want);
        assert_eq!(run(&exprs, &tcp_pkt(0x10, &[]), |c| c.xfrm = Some(&xfrm)), NF_DROP);
    }
}

#[test]
fn a_transport_mode_transform_has_no_addresses_of_its_own() {
    let mut saddr = [0u8; 16];
    saddr[..4].copy_from_slice(&[10, 1, 1, 1]);
    let transport = Xfrm { state: Some(XfrmState { family: NFPROTO_IPV4, saddr,
        daddr: [0u8; 16], reqid: 1, spi: 1, tunnel_mode: false }) };
    let exprs = match_key(Expr::Xfrm { dreg: NFT_REG_1, key: NFT_XFRM_KEY_SADDR_IP4,
                                       dir: 0, spnum: 0 }, &[10, 1, 1, 1]);
    assert_eq!(run(&exprs, &tcp_pkt(0x10, &[]), |c| c.xfrm = Some(&transport)), NFT_BREAK);
    let tunnel = Xfrm { state: Some(XfrmState { tunnel_mode: true,
        ..transport.state.unwrap() }) };
    assert_eq!(run(&exprs, &tcp_pkt(0x10, &[]), |c| c.xfrm = Some(&tunnel)), NF_DROP);
}

#[test]
fn a_transform_key_with_no_security_path_breaks() {
    let exprs = match_key(Expr::Xfrm { dreg: NFT_REG_1, key: NFT_XFRM_KEY_SPI, dir: 0,
                                       spnum: 0 }, &0u32.to_ne_bytes());
    assert_eq!(run(&exprs, &tcp_pkt(0x10, &[]), |_| {}), NFT_BREAK);
    let empty = Xfrm { state: None };
    assert_eq!(run(&exprs, &tcp_pkt(0x10, &[]), |c| c.xfrm = Some(&empty)), NFT_BREAK);
}

#[test]
fn tunnel_metadata_answers_only_in_the_mode_it_was_carried_in() {
    let rx = Tunnel { mode: NFT_TUNNEL_MODE_RX, id: Some(4242) };
    let path = match_key(Expr::Tunnel { dreg: NFT_REG_1, key: NFT_TUNNEL_PATH,
                                        mode: NFT_TUNNEL_MODE_RX }, &[1]);
    assert_eq!(run(&path, &tcp_pkt(0x10, &[]), |c| c.tunnel = Some(&rx)), NF_DROP);
    let wrong = match_key(Expr::Tunnel { dreg: NFT_REG_1, key: NFT_TUNNEL_PATH,
                                         mode: NFT_TUNNEL_MODE_TX }, &[0]);
    assert_eq!(run(&wrong, &tcp_pkt(0x10, &[]), |c| c.tunnel = Some(&rx)), NF_DROP);
    let id = match_key(Expr::Tunnel { dreg: NFT_REG_1, key: NFT_TUNNEL_ID,
                                      mode: NFT_TUNNEL_MODE_TX }, &4242u32.to_ne_bytes());
    assert_eq!(run(&id, &tcp_pkt(0x10, &[]), |c| c.tunnel = Some(&rx)), NFT_BREAK);
}

#[test]
fn a_tunnel_key_with_no_metadata_breaks() {
    let exprs = match_key(Expr::Tunnel { dreg: NFT_REG_1, key: NFT_TUNNEL_PATH,
                                         mode: NFT_TUNNEL_MODE_RX }, &[0]);
    assert_eq!(run(&exprs, &tcp_pkt(0x10, &[]), |_| {}), NFT_BREAK);
}

// --- header options ---

#[test]
fn the_option_walker_handles_the_single_byte_kinds() {
    // A no-operation is one byte with no length field. Reading a length there
    // consumes the following option's kind and desynchronises the walk.
    assert_eq!(tcp_optlen(&[1, 1, 2, 4], 0), 1);
    assert_eq!(tcp_optlen(&[0, 1, 2, 4], 0), 1);
    assert_eq!(tcp_optlen(&[2, 4, 0x05, 0xb4], 0), 4);
    assert_eq!(tcp_optlen(&[2], 0), 1, "a length that is not there cannot advance zero");
}

#[test]
fn a_tcp_option_is_found_past_padding() {
    // NOP, NOP, window scale (kind 3, length 3), maximum segment size.
    let options = [1u8, 1, 3, 3, 7, 2, 4, 0x05, 0xb4];
    let header = fixture::tcp(1234, 80, 0x02, &options);
    assert_eq!(find_tcp_option(&header, 3), Some((22, 3)));
    assert_eq!(find_tcp_option(&header, 2), Some((25, 4)));
    assert_eq!(find_tcp_option(&header, 8), None, "an absent kind is not invented");
}

#[test]
fn the_option_walk_stops_at_the_end_marker() {
    let options = [0u8, 3, 3, 7];
    let header = fixture::tcp(1234, 80, 0x02, &options);
    assert_eq!(find_tcp_option(&header, 3), None,
        "anything past the end marker is padding, not an option");
}

#[test]
fn a_tcp_option_read_gives_its_bytes_and_an_absent_one_breaks() {
    let options = [3u8, 3, 7, 0];
    let pkt = tcp_pkt(0x02, &options);
    let exprs = match_key(Expr::Exthdr { dreg: Some(NFT_REG_1), sreg: None,
        op: NFT_EXTHDR_OP_TCPOPT, htype: 3, offset: 2, len: 1, flags: 0 }, &[7]);
    assert_eq!(run(&exprs, &pkt, |c| c.meta.l4proto = Some(6)), NF_DROP);

    let absent = match_key(Expr::Exthdr { dreg: Some(NFT_REG_1), sreg: None,
        op: NFT_EXTHDR_OP_TCPOPT, htype: 8, offset: 2, len: 1, flags: 0 }, &[0]);
    assert_eq!(run(&absent, &pkt, |c| c.meta.l4proto = Some(6)), NFT_BREAK);
}

#[test]
fn the_presence_flag_reports_a_boolean_for_a_missing_option() {
    let pkt = tcp_pkt(0x02, &[3, 3, 7, 0]);
    let there = match_key(Expr::Exthdr { dreg: Some(NFT_REG_1), sreg: None,
        op: NFT_EXTHDR_OP_TCPOPT, htype: 3, offset: 0, len: 1,
        flags: NFT_EXTHDR_F_PRESENT }, &[1]);
    assert_eq!(run(&there, &pkt, |c| c.meta.l4proto = Some(6)), NF_DROP);
    let missing = match_key(Expr::Exthdr { dreg: Some(NFT_REG_1), sreg: None,
        op: NFT_EXTHDR_OP_TCPOPT, htype: 8, offset: 0, len: 1,
        flags: NFT_EXTHDR_F_PRESENT }, &[0]);
    assert_eq!(run(&missing, &pkt, |c| c.meta.l4proto = Some(6)), NF_DROP);
}

#[test]
fn a_read_past_the_end_of_an_option_breaks() {
    // Two options back to back: window scale (kind 3, three bytes) followed by
    // maximum segment size. Reading four bytes from the first would succeed
    // against the buffer and hand back the second option's bytes, so the
    // bound has to be the option's own length, not the buffer's.
    let options = [3u8, 3, 7, 2, 4, 0x05, 0xb4, 0];
    let pkt = tcp_pkt(0x02, &options);
    let good = match_key(Expr::Exthdr { dreg: Some(NFT_REG_1), sreg: None,
        op: NFT_EXTHDR_OP_TCPOPT, htype: 3, offset: 2, len: 1, flags: 0 }, &[7]);
    assert_eq!(run(&good, &pkt, |c| c.meta.l4proto = Some(6)), NF_DROP);

    let over = match_key(Expr::Exthdr { dreg: Some(NFT_REG_1), sreg: None,
        op: NFT_EXTHDR_OP_TCPOPT, htype: 3, offset: 2, len: 4, flags: 0 },
        &[7, 2, 4, 0x05]);
    assert_eq!(run(&over, &pkt, |c| c.meta.l4proto = Some(6)), NFT_BREAK,
        "the neighbouring option's bytes must not be readable through this one");

    // An offset past the option is equally out of bounds.
    let past = match_key(Expr::Exthdr { dreg: Some(NFT_REG_1), sreg: None,
        op: NFT_EXTHDR_OP_TCPOPT, htype: 3, offset: 3, len: 1, flags: 0 }, &[2]);
    assert_eq!(run(&past, &pkt, |c| c.meta.l4proto = Some(6)), NFT_BREAK);
}

#[test]
fn writing_and_stripping_an_option_are_recorded_as_effects() {
    let pkt = tcp_pkt(0x02, &[3, 3, 7, 0]);
    let write = vec![
        Expr::Immediate { dreg: NFT_REG_1, verdict: None, chain: None, value: alloc::vec![5] },
        Expr::Exthdr { dreg: None, sreg: Some(NFT_REG_1), op: NFT_EXTHDR_OP_TCPOPT,
                       htype: 3, offset: 2, len: 1, flags: 0 },
    ];
    let states = ExprStates::for_exprs(&write);
    let mut ctx = EvalCtx::ipv4(&pkt, &states);
    ctx.meta.l4proto = Some(6);
    assert_eq!(run_rule_ctx(&write, &mut ctx).code, NFT_CONTINUE);
    assert!(matches!(&ctx.actions[..], [Action::ExthdrSet { htype: 3, offset: 2, .. }]));

    let strip = vec![Expr::Exthdr { dreg: None, sreg: None, op: NFT_EXTHDR_OP_TCPOPT,
                                    htype: 3, offset: 0, len: 0, flags: 0 }];
    let states = ExprStates::for_exprs(&strip);
    let mut ctx = EvalCtx::ipv4(&pkt, &states);
    ctx.meta.l4proto = Some(6);
    assert_eq!(run_rule_ctx(&strip, &mut ctx).code, NFT_CONTINUE);
    assert!(matches!(&ctx.actions[..], [Action::ExthdrStrip { htype: 3, .. }]));
}

#[test]
fn an_ipv4_option_walk_finds_only_the_reportable_kinds() {
    // Header length six words: twenty fixed bytes plus four of options.
    let mut pkt = fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &[]);
    pkt[0] = 0x46;
    pkt.splice(20..20, [0x94u8, 4, 0, 0]);
    assert_eq!(find_ipv4_option(&pkt, 0x94), Some((20, 4)), "the router-alert option");
    assert_eq!(find_ipv4_option(&pkt, 7), None, "record-route is absent here");
    assert_eq!(find_ipv4_option(&pkt, 68), None, "a timestamp is never reported");
}

#[test]
fn an_ipv6_extension_walk_finds_a_chained_header() {
    // Fixed header naming a hop-by-hop header, which names a routing header.
    let mut pkt = alloc::vec![0u8; 40];
    pkt[0] = 0x60;
    pkt[6] = 0;
    pkt.extend_from_slice(&[43, 0, 0, 0, 0, 0, 0, 0]);
    pkt.extend_from_slice(&[59, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(find_ipv6_exthdr(&pkt, 0), Some((40, 8)));
    assert_eq!(find_ipv6_exthdr(&pkt, 43), Some((48, 8)));
    assert_eq!(find_ipv6_exthdr(&pkt, 60), None);
}

#[test]
fn an_sctp_chunk_walk_honours_word_padding() {
    // Two chunks: type 1 of length 5 (padded to eight), then type 2.
    let mut body = alloc::vec![0u8; 12];
    body.extend_from_slice(&[1, 0, 0, 5, 0, 0, 0, 0]);
    body.extend_from_slice(&[2, 0, 0, 4]);
    assert_eq!(find_sctp_chunk(&body, 1), Some((12, 5)));
    assert_eq!(find_sctp_chunk(&body, 2), Some((20, 4)),
        "a chunk that is not word-aligned still advances by a whole word");
    assert_eq!(find_sctp_chunk(&body, 9), None);
}

#[test]
fn a_zero_length_chunk_cannot_loop_the_walk() {
    let mut body = alloc::vec![0u8; 12];
    body.extend_from_slice(&[1, 0, 0, 0]);
    assert_eq!(find_sctp_chunk(&body, 9), None);
}

#[test]
fn an_option_walker_refuses_the_wrong_family() {
    let v4 = tcp_pkt(0x02, &[]);
    let exprs = match_key(Expr::Exthdr { dreg: Some(NFT_REG_1), sreg: None,
        op: NFT_EXTHDR_OP_IPV6, htype: 0, offset: 0, len: 1, flags: 0 }, &[0]);
    assert_eq!(run(&exprs, &v4, |_| {}), NFT_BREAK);
}
