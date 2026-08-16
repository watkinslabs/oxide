// The `meta` key set. Most keys read something the context may not carry, and
// the rule that matters is the same for all of them: absent means break, never
// zero — a rule testing `meta mark 0` must not be satisfied by "no mark".

extern crate alloc;
use alloc::vec;

use crate::nft_expr::ctx::{EvalCtx, IfInfo};
use crate::nft_expr::expr::Expr;
use crate::nft_expr::limits::IFNAMSIZ;
use crate::nft_expr::run::meta::{pkttype_compatible, PACKET_BROADCAST, PACKET_HOST,
                                 PACKET_MULTICAST, PACKET_OTHERHOST};
use crate::nft_expr::run::{run_rule_ctx, run_rule_regs};
use crate::nft_expr::regs::Regs;
use crate::nft_expr::stateful::ExprStates;
use crate::nft_expr::uapi::*;
use super::fixture;

fn named(name: &[u8], index: u32) -> IfInfo {
    let mut n = [0u8; IFNAMSIZ];
    n[..name.len()].copy_from_slice(name);
    let mut kind = [0u8; IFNAMSIZ];
    kind[..4].copy_from_slice(b"vlan");
    IfInfo { index, name: n, kind, iftype: 1, group: 9 }
}

fn drop_now() -> Expr {
    Expr::Immediate { dreg: NFT_REG_VERDICT, verdict: Some(NF_DROP), chain: None,
                      value: alloc::vec::Vec::new() }
}

fn match_meta(key: u32, want: &[u8], setup: impl FnOnce(&mut EvalCtx)) -> i32 {
    let exprs = vec![
        Expr::Meta { dreg: Some(NFT_REG_1), sreg: None, key },
        Expr::Cmp { sreg: NFT_REG_1, op: NFT_CMP_EQ, data: want.to_vec() },
        drop_now(),
    ];
    let states = ExprStates::for_exprs(&exprs);
    let pkt = fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &fixture::tcp(1, 2, 0x10, &[]));
    let mut ctx = EvalCtx::ipv4(&pkt, &states);
    setup(&mut ctx);
    run_rule_ctx(&exprs, &mut ctx).code
}

#[test]
fn the_keys_that_always_have_an_answer() {
    let pkt_len = 20 + 20;
    assert_eq!(match_meta(NFT_META_LEN, &(pkt_len as u32).to_ne_bytes(), |_| {}), NF_DROP);
    assert_eq!(match_meta(NFT_META_NFPROTO, &[NFPROTO_IPV4], |_| {}), NF_DROP);
    assert_eq!(match_meta(NFT_META_MARK, &0x42u32.to_ne_bytes(), |c| c.mark = 0x42), NF_DROP);
    assert_eq!(match_meta(NFT_META_PRIORITY, &7u32.to_ne_bytes(),
        |c| c.meta.priority = 7), NF_DROP);
    assert_eq!(match_meta(NFT_META_SECMARK, &5u32.to_ne_bytes(),
        |c| c.meta.secmark = 5), NF_DROP);
    assert_eq!(match_meta(NFT_META_CPU, &3u32.to_ne_bytes(), |c| c.cpu = 3), NF_DROP);
    assert_eq!(match_meta(NFT_META_PRANDOM, &9u32.to_ne_bytes(),
        |c| c.meta.prandom = 9), NF_DROP);
    assert_eq!(match_meta(NFT_META_NFTRACE, &[1], |c| c.meta.nftrace = true), NF_DROP);
    assert_eq!(match_meta(NFT_META_SECPATH, &[1], |c| c.meta.secpath = true), NF_DROP);
}

#[test]
fn the_link_protocol_is_reported_in_network_order() {
    // Userspace compares against the wire value; a host-order answer matches
    // a different protocol entirely on a little-endian machine.
    assert_eq!(match_meta(NFT_META_PROTOCOL, &0x0800u16.to_be_bytes(),
        |c| c.meta.protocol = Some(0x0800)), NF_DROP);
    // The host-order spelling of the same number must NOT match on a
    // little-endian machine, which is what makes the assertion above real.
    if 0x0800u16.to_ne_bytes() != 0x0800u16.to_be_bytes() {
        assert_eq!(match_meta(NFT_META_PROTOCOL, &0x0800u16.to_ne_bytes(),
            |c| c.meta.protocol = Some(0x0800)), NFT_BREAK);
    }
}

#[test]
fn the_transport_protocol_comes_from_the_header() {
    assert_eq!(match_meta(NFT_META_L4PROTO, &[6], |c| c.meta.l4proto = Some(6)), NF_DROP);
    assert_eq!(match_meta(NFT_META_L4PROTO, &[17], |c| c.meta.l4proto = Some(6)), NFT_BREAK);
}

#[test]
fn interface_keys_read_the_interface_they_name() {
    let iif = named(b"eth0", 2);
    let oif = named(b"eth1", 3);
    let setup = |c: &mut EvalCtx| { c.meta.iif = Some(iif); c.meta.oif = Some(oif); };
    assert_eq!(match_meta(NFT_META_IIF, &2u32.to_ne_bytes(), setup), NF_DROP);
    assert_eq!(match_meta(NFT_META_OIF, &3u32.to_ne_bytes(), setup), NF_DROP);
    assert_eq!(match_meta(NFT_META_IIFNAME, &iif.name, setup), NF_DROP);
    assert_eq!(match_meta(NFT_META_OIFNAME, &oif.name, setup), NF_DROP);
    assert_eq!(match_meta(NFT_META_IIFKIND, &iif.kind, setup), NF_DROP);
    assert_eq!(match_meta(NFT_META_IIFTYPE, &1u16.to_ne_bytes(), setup), NF_DROP);
    assert_eq!(match_meta(NFT_META_IIFGROUP, &9u32.to_ne_bytes(), setup), NF_DROP);
    // Reading the output side when only the input side exists is the classic
    // confusion; it must break rather than answer with the other interface.
    assert_eq!(match_meta(NFT_META_OIF, &2u32.to_ne_bytes(),
        |c| c.meta.iif = Some(iif)), NFT_BREAK);
}

#[test]
fn an_absent_source_breaks_rather_than_reading_zero() {
    // Each of these would otherwise silently satisfy a rule that tests for a
    // zero value, which is a common way to write "unset".
    let zero4 = 0u32.to_ne_bytes();
    for key in [NFT_META_IIF, NFT_META_OIF, NFT_META_SDIF, NFT_META_IIFGROUP,
                NFT_META_OIFGROUP, NFT_META_SKUID, NFT_META_SKGID, NFT_META_RTCLASSID,
                NFT_META_CGROUP, NFT_META_TIME_HOUR]
    { assert_eq!(match_meta(key, &zero4, |_| {}), NFT_BREAK, "key {key}"); }
    for key in [NFT_META_IIFNAME, NFT_META_OIFNAME, NFT_META_IIFKIND, NFT_META_OIFKIND,
                NFT_META_SDIFNAME, NFT_META_BRI_IIFNAME, NFT_META_BRI_OIFNAME]
    { assert_eq!(match_meta(key, &[0u8; IFNAMSIZ], |_| {}), NFT_BREAK, "key {key}"); }
    assert_eq!(match_meta(NFT_META_PKTTYPE, &[0], |_| {}), NFT_BREAK);
    assert_eq!(match_meta(NFT_META_PROTOCOL, &0u16.to_be_bytes(), |_| {}), NFT_BREAK);
    assert_eq!(match_meta(NFT_META_TIME_NS, &0u64.to_ne_bytes(), |_| {}), NFT_BREAK);
    assert_eq!(match_meta(NFT_META_TIME_DAY, &[0], |_| {}), NFT_BREAK);
}

#[test]
fn the_socket_owner_keys_report_the_credentials_they_were_given() {
    assert_eq!(match_meta(NFT_META_SKUID, &1000u32.to_ne_bytes(),
        |c| c.meta.skuid = Some(1000)), NF_DROP);
    assert_eq!(match_meta(NFT_META_SKGID, &1000u32.to_ne_bytes(),
        |c| c.meta.skgid = Some(1000)), NF_DROP);
    assert_eq!(match_meta(NFT_META_CGROUP, &42u32.to_ne_bytes(),
        |c| c.meta.cgroup = Some(42)), NF_DROP);
}

#[test]
fn the_time_keys_report_what_the_clock_gave() {
    let setup = |c: &mut EvalCtx| {
        c.meta.time_ns = Some(1_000_000_000);
        c.meta.time_day = Some(3);
        c.meta.time_hour = Some(3600);
    };
    assert_eq!(match_meta(NFT_META_TIME_NS, &1_000_000_000u64.to_ne_bytes(), setup), NF_DROP);
    assert_eq!(match_meta(NFT_META_TIME_DAY, &[3], setup), NF_DROP);
    assert_eq!(match_meta(NFT_META_TIME_HOUR, &3600u32.to_ne_bytes(), setup), NF_DROP);
}

#[test]
fn the_bridge_keys_read_the_bridge_port() {
    let bri = named(b"br0", 4);
    let setup = |c: &mut EvalCtx| {
        c.meta.bri_iif = Some(bri);
        c.meta.bri_iif_pvid = Some(100);
        c.meta.bri_iif_vproto = Some(0x8100);
        c.meta.bri_broute = Some(1);
        c.meta.bri_iif_hwaddr = Some([1, 2, 3, 4, 5, 6]);
    };
    assert_eq!(match_meta(NFT_META_BRI_IIFNAME, &bri.name, setup), NF_DROP);
    assert_eq!(match_meta(NFT_META_BRI_IIFPVID, &100u16.to_ne_bytes(), setup), NF_DROP);
    assert_eq!(match_meta(NFT_META_BRI_IIFVPROTO, &0x8100u16.to_be_bytes(), setup), NF_DROP);
    assert_eq!(match_meta(NFT_META_BRI_BROUTE, &[1], setup), NF_DROP);
    assert_eq!(match_meta(NFT_META_BRI_IIFHWADDR, &[1, 2, 3, 4, 5, 6], setup), NF_DROP);
}

#[test]
fn a_mark_written_by_one_rule_is_read_by_the_next() {
    let exprs = vec![
        Expr::Immediate { dreg: NFT_REG_1, verdict: None, chain: None,
                          value: 0x1234u32.to_ne_bytes().to_vec() },
        Expr::Meta { dreg: None, sreg: Some(NFT_REG_1), key: NFT_META_MARK },
        Expr::Meta { dreg: Some(NFT_REG_2), sreg: None, key: NFT_META_MARK },
        Expr::Cmp { sreg: NFT_REG_2, op: NFT_CMP_EQ, data: 0x1234u32.to_ne_bytes().to_vec() },
        drop_now(),
    ];
    let states = ExprStates::for_exprs(&exprs);
    let pkt = fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &[]);
    let mut ctx = EvalCtx::ipv4(&pkt, &states);
    assert_eq!(run_rule_ctx(&exprs, &mut ctx).code, NF_DROP);
    assert_eq!(ctx.mark, 0x1234, "the mark outlives the rule that set it");
}

#[test]
fn the_writable_keys_are_written_and_the_rest_refused() {
    for (key, read_back) in [
        (NFT_META_MARK, 0), (NFT_META_PRIORITY, 1), (NFT_META_SECMARK, 2),
        (NFT_META_NFTRACE, 3)]
    {
        let exprs = vec![
            Expr::Immediate { dreg: NFT_REG_1, verdict: None, chain: None,
                              value: 1u32.to_ne_bytes().to_vec() },
            Expr::Meta { dreg: None, sreg: Some(NFT_REG_1), key },
        ];
        let states = ExprStates::for_exprs(&exprs);
        let pkt = fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &[]);
        let mut ctx = EvalCtx::ipv4(&pkt, &states);
        assert_eq!(run_rule_ctx(&exprs, &mut ctx).code, NFT_CONTINUE, "key {key}");
        match read_back {
            0 => assert_eq!(ctx.mark, 1),
            1 => assert_eq!(ctx.meta.priority, 1),
            2 => assert_eq!(ctx.meta.secmark, 1),
            _ => assert!(ctx.meta.nftrace),
        }
    }
    // A read-only key must not be silently accepted as a write.
    for key in [NFT_META_LEN, NFT_META_IIF, NFT_META_L4PROTO, NFT_META_NFPROTO] {
        let exprs = vec![
            Expr::Immediate { dreg: NFT_REG_1, verdict: None, chain: None,
                              value: 1u32.to_ne_bytes().to_vec() },
            Expr::Meta { dreg: None, sreg: Some(NFT_REG_1), key },
        ];
        let states = ExprStates::for_exprs(&exprs);
        let pkt = fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &[]);
        let mut ctx = EvalCtx::ipv4(&pkt, &states);
        assert_eq!(run_rule_ctx(&exprs, &mut ctx).code, NFT_BREAK, "key {key}");
    }
}

#[test]
fn a_delivery_class_may_only_move_where_the_link_layer_could_have_put_it() {
    // Turning a packet addressed to another host into one addressed to us is
    // how a rule would make the stack deliver traffic it must not see.
    assert!(!pkttype_compatible(Some(PACKET_HOST), PACKET_OTHERHOST));
    assert!(pkttype_compatible(Some(PACKET_OTHERHOST), PACKET_HOST));
    assert!(pkttype_compatible(Some(PACKET_MULTICAST), PACKET_HOST));
    assert!(pkttype_compatible(Some(PACKET_BROADCAST), PACKET_MULTICAST));
    assert!(!pkttype_compatible(Some(PACKET_MULTICAST), PACKET_OTHERHOST));
    assert!(!pkttype_compatible(None, PACKET_HOST), "an unknown class cannot be moved");
}

#[test]
fn writing_an_incompatible_delivery_class_leaves_it_alone() {
    let exprs = vec![
        Expr::Immediate { dreg: NFT_REG_1, verdict: None, chain: None,
                          value: alloc::vec![PACKET_OTHERHOST] },
        Expr::Meta { dreg: None, sreg: Some(NFT_REG_1), key: NFT_META_PKTTYPE },
    ];
    let states = ExprStates::for_exprs(&exprs);
    let pkt = fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &[]);
    let mut ctx = EvalCtx::ipv4(&pkt, &states);
    ctx.meta.pkttype = Some(PACKET_HOST);
    run_rule_ctx(&exprs, &mut ctx);
    assert_eq!(ctx.meta.pkttype, Some(PACKET_HOST));
}

#[test]
fn a_key_stores_exactly_its_own_width() {
    // A wider store would overwrite the neighbouring register a later
    // expression is about to read.
    let exprs = vec![
        Expr::Immediate { dreg: NFT_REG_1, verdict: None, chain: None,
                          value: alloc::vec![0xff; 16] },
        Expr::Meta { dreg: Some(NFT_REG_1), sreg: None, key: NFT_META_NFPROTO },
    ];
    let states = ExprStates::for_exprs(&exprs);
    let pkt = fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &[]);
    let mut ctx = EvalCtx::ipv4(&pkt, &states);
    let mut regs = Regs::new();
    run_rule_regs(&exprs, &mut ctx, &mut regs);
    let got = regs.load(NFT_REG_1, 4).unwrap();
    assert_eq!(got[0], NFPROTO_IPV4);
    assert_eq!(&got[1..], &[0, 0, 0], "the rest of the word is cleared, not left over");
}
