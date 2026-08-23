// Register-to-register selection: range, hash, objref, and the payload set
// direction. A bound compared the wrong way round admits the complement of
// what the rule asked for, which is the failure worth pinning.

extern crate alloc;
use alloc::vec;

use crate::nft_expr::action::Action;
use crate::nft_expr::ctx::EvalCtx;
use crate::nft_expr::expr::Expr;
use crate::nft_expr::flags::NFT_PAYLOAD_L4CSUM_PSEUDOHDR;
use crate::nft_expr::hashing::jhash;
use crate::nft_expr::run::{run_rule_ctx, run_rule_regs};
use crate::nft_expr::regs::Regs;
use crate::nft_expr::stateful::ExprStates;
use crate::nft_expr::uapi::*;
use super::fixture;

fn imm(reg: u32, bytes: &[u8]) -> Expr {
    Expr::Immediate { dreg: reg, verdict: None, chain: None, value: bytes.to_vec() }
}

fn drop_now() -> Expr {
    Expr::Immediate { dreg: NFT_REG_VERDICT, verdict: Some(NF_DROP), chain: None,
                      value: alloc::vec::Vec::new() }
}

fn run(exprs: &[Expr], pkt: &[u8]) -> i32 {
    let states = ExprStates::for_exprs(exprs);
    let mut ctx = EvalCtx::ipv4(pkt, &states);
    run_rule_ctx(exprs, &mut ctx).code
}

fn regs_with_ct<'a>(exprs: &[Expr], pkt: &'a [u8], ct: &'a super::fixture::Ct) -> Regs {
    let states = ExprStates::for_exprs(exprs);
    let mut ctx = EvalCtx::ipv4(pkt, &states);
    ctx.ct = Some(ct);
    let mut regs = Regs::new();
    run_rule_regs(exprs, &mut ctx, &mut regs);
    regs
}

fn regs_after(exprs: &[Expr], pkt: &[u8]) -> Regs {
    let states = ExprStates::for_exprs(exprs);
    let mut ctx = EvalCtx::ipv4(pkt, &states);
    let mut regs = Regs::new();
    run_rule_regs(exprs, &mut ctx, &mut regs);
    regs
}

fn port_range(op: u32, from: u16, to: u16, port: u16) -> i32 {
    let exprs = vec![
        imm(NFT_REG_1, &port.to_be_bytes()),
        Expr::Range { sreg: NFT_REG_1, op, from: from.to_be_bytes().to_vec(),
                      to: to.to_be_bytes().to_vec() },
        drop_now(),
    ];
    run(&exprs, &[])
}

#[test]
fn notrack_marks_the_raw_stage_without_changing_the_verdict() {
    let exprs = vec![Expr::Notrack];
    let states = ExprStates::empty();
    let mut ctx = EvalCtx::ipv4(&[], &states);
    assert_eq!(run_rule_ctx(&exprs, &mut ctx).code, NFT_CONTINUE);
    assert!(ctx.notrack);
}

#[test]
fn a_range_is_inclusive_at_both_ends() {
    // Ports 1000 to 2000. The bounds themselves are inside the range; a
    // strict comparison at either end silently exempts a port the rule names.
    assert_eq!(port_range(NFT_RANGE_EQ, 1000, 2000, 999), NFT_BREAK);
    assert_eq!(port_range(NFT_RANGE_EQ, 1000, 2000, 1000), NF_DROP);
    assert_eq!(port_range(NFT_RANGE_EQ, 1000, 2000, 1500), NF_DROP);
    assert_eq!(port_range(NFT_RANGE_EQ, 1000, 2000, 2000), NF_DROP);
    assert_eq!(port_range(NFT_RANGE_EQ, 1000, 2000, 2001), NFT_BREAK);
}

#[test]
fn an_inverted_range_is_exactly_the_complement() {
    for port in [999u16, 1000, 1500, 2000, 2001] {
        let inside = port_range(NFT_RANGE_EQ, 1000, 2000, port) == NF_DROP;
        let outside = port_range(NFT_RANGE_NEQ, 1000, 2000, port) == NF_DROP;
        assert_ne!(inside, outside, "port {port} must be in exactly one of the two");
    }
}

#[test]
fn a_single_value_range_matches_only_that_value() {
    assert_eq!(port_range(NFT_RANGE_EQ, 22, 22, 22), NF_DROP);
    assert_eq!(port_range(NFT_RANGE_EQ, 22, 22, 23), NFT_BREAK);
    assert_eq!(port_range(NFT_RANGE_EQ, 22, 22, 21), NFT_BREAK);
}

#[test]
fn a_range_compares_the_bytes_in_the_order_they_were_given() {
    // Network-order bytes compare left to right. Comparing them as a
    // host-order integer reverses the ordering for every multi-byte value.
    assert_eq!(port_range(NFT_RANGE_EQ, 0x0100, 0x0200, 0x0180), NF_DROP);
    assert_eq!(port_range(NFT_RANGE_EQ, 0x0100, 0x0200, 0x0080), NFT_BREAK);
    assert_eq!(port_range(NFT_RANGE_EQ, 0x0100, 0x0200, 0x0280), NFT_BREAK);
}

#[test]
fn a_wide_range_compares_the_whole_width() {
    // An address range: only the last octet differs, so a comparison that
    // stops early admits the whole prefix.
    let exprs = vec![
        imm(NFT_REG_1, &[10, 0, 0, 200]),
        Expr::Range { sreg: NFT_REG_1, op: NFT_RANGE_EQ,
                      from: alloc::vec![10, 0, 0, 100], to: alloc::vec![10, 0, 0, 150] },
        drop_now(),
    ];
    assert_eq!(run(&exprs, &[]), NFT_BREAK);
}

#[test]
fn the_hash_lands_inside_its_modulus_and_offset() {
    for len in [1u32, 4, 16] {
        let exprs = vec![
            imm(NFT_REG_1, &[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            Expr::Hash { sreg: NFT_REG_1, dreg: NFT_REG_2, len, modulus: 5, seed: 0x1234,
                         offset: 100, hash_type: NFT_HASH_JENKINS },
        ];
        let regs = regs_after(&exprs, &[]);
        let v = u32::from_ne_bytes(regs.load(NFT_REG_2, 4).unwrap().try_into().unwrap());
        assert!((100..105).contains(&v), "len {len} produced {v}");
    }
}

#[test]
fn the_hash_reads_only_the_length_it_was_given() {
    // A hash over more bytes than the rule asked for folds in register
    // contents the rule never selected, so two identical keys stop agreeing.
    let base = |tail: u8| vec![
        imm(NFT_REG_1, &[1, 2, 3, 4, tail, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        Expr::Hash { sreg: NFT_REG_1, dreg: NFT_REG_2, len: 4, modulus: 1000, seed: 7,
                     offset: 0, hash_type: NFT_HASH_JENKINS },
    ];
    let a = regs_after(&base(0), &[]);
    let b = regs_after(&base(0xff), &[]);
    assert_eq!(a.load(NFT_REG_2, 4), b.load(NFT_REG_2, 4));
}

#[test]
fn the_hash_seed_changes_the_answer() {
    let with = |seed: u32| vec![
        imm(NFT_REG_1, &[1, 2, 3, 4]),
        Expr::Hash { sreg: NFT_REG_1, dreg: NFT_REG_2, len: 4, modulus: 100_000, seed,
                     offset: 0, hash_type: NFT_HASH_JENKINS },
    ];
    let a = regs_after(&with(1), &[]);
    let b = regs_after(&with(2), &[]);
    assert_ne!(a.load(NFT_REG_2, 4), b.load(NFT_REG_2, 4));
}

#[test]
fn the_byte_hash_is_stable_and_length_sensitive() {
    assert_eq!(jhash(b"abcd", 0), jhash(b"abcd", 0));
    assert_ne!(jhash(b"abcd", 0), jhash(b"abce", 0));
    assert_ne!(jhash(b"abcd", 0), jhash(b"abcd", 1));
    assert_ne!(jhash(b"abcd", 0), jhash(b"abcdd", 0));
}

#[test]
fn a_symmetric_hash_agrees_for_both_directions_of_one_flow() {
    // The point of the symmetric form: a request and its reply must reach the
    // same bucket, or a per-flow decision splits across the two halves. It is
    // formed from the tracked flow, so both directions read the one tuple.
    use super::fixture::Ct;
    let flow = Ct { attached: true,
        tuples: [Some(super::fixture::tuple4([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80)),
                 Some(super::fixture::tuple4([10, 0, 0, 2], 80, [10, 0, 0, 1], 1234))],
        ..Ct::default() };
    let other = Ct { attached: true,
        tuples: [Some(super::fixture::tuple4([10, 0, 0, 9], 5555, [10, 0, 0, 8], 443)), None],
        ..Ct::default() };
    let exprs = vec![Expr::Hash { sreg: NFT_REG_1, dreg: NFT_REG_2, len: 0, modulus: 64,
                                  seed: 0, offset: 0, hash_type: NFT_HASH_SYM }];

    let out = fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2],
                            &fixture::tcp(1234, 80, 0x10, &[]));
    let back = fixture::ipv4(6, [10, 0, 0, 2], [10, 0, 0, 1],
                             &fixture::tcp(80, 1234, 0x10, &[]));
    let a = regs_with_ct(&exprs, &out, &flow);
    let b = regs_with_ct(&exprs, &back, &flow);
    assert_eq!(a.load(NFT_REG_2, 4), b.load(NFT_REG_2, 4));

    let c = regs_with_ct(&exprs, &out, &other);
    assert_ne!(a.load(NFT_REG_2, 4), c.load(NFT_REG_2, 4),
        "a different conversation must not collapse onto it");
}

#[test]
fn a_symmetric_hash_without_a_tracked_flow_breaks() {
    // Falling back to a zero would put every untracked packet in one bucket.
    let exprs = vec![Expr::Hash { sreg: NFT_REG_1, dreg: NFT_REG_2, len: 0, modulus: 64,
                                  seed: 0, offset: 0, hash_type: NFT_HASH_SYM }];
    assert_eq!(run(&exprs, &[]), NFT_BREAK);
}

#[test]
fn a_payload_write_is_recorded_with_its_checksum_request() {
    let pkt = fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2],
                            &fixture::tcp(1234, 80, 0x10, &[]));
    let exprs = vec![
        imm(NFT_REG_1, &8080u16.to_be_bytes()),
        Expr::Payload { dreg: 0, base: NFT_PAYLOAD_TRANSPORT_HEADER, offset: 2, len: 2,
                        sreg: Some(NFT_REG_1), csum_type: NFT_PAYLOAD_CSUM_INET,
                        csum_offset: 16, csum_flags: NFT_PAYLOAD_L4CSUM_PSEUDOHDR },
    ];
    let states = ExprStates::for_exprs(&exprs);
    let mut ctx = EvalCtx::ipv4(&pkt, &states);
    ctx.meta.l4proto = Some(6);
    assert_eq!(run_rule_ctx(&exprs, &mut ctx).code, NFT_CONTINUE);
    match &ctx.actions[..] {
        [Action::PayloadSet { base, offset, data, csum_type, csum_offset, csum_flags }] => {
            assert_eq!(*base, NFT_PAYLOAD_TRANSPORT_HEADER);
            assert_eq!(*offset, 2);
            assert_eq!(data, &8080u16.to_be_bytes().to_vec());
            assert_eq!(*csum_type, NFT_PAYLOAD_CSUM_INET);
            assert_eq!((*csum_offset, *csum_flags), (16, NFT_PAYLOAD_L4CSUM_PSEUDOHDR));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_payload_read_past_the_packet_breaks_rather_than_reading_rubbish() {
    let short = fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &[]);
    let exprs = vec![
        Expr::Payload { dreg: NFT_REG_1, base: NFT_PAYLOAD_TRANSPORT_HEADER, offset: 0,
                        len: 4, sreg: None, csum_type: 0, csum_offset: 0, csum_flags: 0 },
        drop_now(),
    ];
    let states = ExprStates::for_exprs(&exprs);
    let mut ctx = EvalCtx::ipv4(&short, &states);
    ctx.meta.l4proto = Some(6);
    assert_eq!(run_rule_ctx(&exprs, &mut ctx).code, NFT_BREAK);
}

#[test]
fn the_inner_header_base_reads_the_decapsulated_packet() {
    let outer = fixture::ipv4(4, [10, 0, 0, 1], [10, 0, 0, 2], &[]);
    let inner = fixture::ipv4(6, [192, 168, 1, 1], [192, 168, 1, 2], &[]);
    let exprs = vec![
        Expr::Payload { dreg: NFT_REG_1, base: NFT_PAYLOAD_INNER_HEADER, offset: 12,
                        len: 4, sreg: None, csum_type: 0, csum_offset: 0, csum_flags: 0 },
        Expr::Cmp { sreg: NFT_REG_1, op: NFT_CMP_EQ, data: alloc::vec![192, 168, 1, 1] },
        drop_now(),
    ];
    let states = ExprStates::for_exprs(&exprs);
    let mut ctx = EvalCtx::ipv4(&outer, &states);
    ctx.inner = &inner;
    assert_eq!(run_rule_ctx(&exprs, &mut ctx).code, NF_DROP);
}

#[test]
fn the_link_header_base_breaks_where_no_link_header_survives() {
    let exprs = vec![
        Expr::Payload { dreg: NFT_REG_1, base: NFT_PAYLOAD_LL_HEADER, offset: 0, len: 6,
                        sreg: None, csum_type: 0, csum_offset: 0, csum_flags: 0 },
        drop_now(),
    ];
    assert_eq!(run(&exprs, &fixture::ipv4(6, [1, 2, 3, 4], [5, 6, 7, 8], &[])), NFT_BREAK);
}

#[test]
fn an_object_reference_runs_the_object_it_names() {
    struct Objects;
    impl crate::nft_expr::access::ObjectAccess for Objects {
        fn eval(&self, _t: u32, name: &str) -> Option<i32> {
            if name == "spent" { Some(NFT_BREAK) } else { None }
        }
    }
    let objects = Objects;
    for (name, want) in [("spent", NFT_BREAK), ("fresh", NF_DROP)] {
        let exprs = vec![
            Expr::Objref { obj_type: Some(1), name: Some(alloc::string::String::from(name)),
                           sreg: None, set: None, set_id: None },
            drop_now(),
        ];
        let states = ExprStates::for_exprs(&exprs);
        let mut ctx = EvalCtx::ipv4(&[], &states);
        ctx.objects = Some(&objects);
        assert_eq!(run_rule_ctx(&exprs, &mut ctx).code, want, "object {name}");
    }
}

#[test]
fn an_object_reference_with_no_object_table_breaks() {
    let exprs = vec![
        Expr::Objref { obj_type: Some(1), name: Some(alloc::string::String::from("q")),
                       sreg: None, set: None, set_id: None },
        drop_now(),
    ];
    assert_eq!(run(&exprs, &[]), NFT_BREAK);
}
