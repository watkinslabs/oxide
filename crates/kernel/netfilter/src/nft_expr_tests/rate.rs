// The counting expressions: limit, quota, connlimit, last. Every one of these
// is a "how much is allowed" decision, so the dangerous direction is letting
// traffic through after the budget is gone.

extern crate alloc;
use alloc::vec;

use crate::nft_expr::ctx::EvalCtx;
use crate::nft_expr::expr::Expr;
use crate::nft_expr::limits::NSEC_PER_SEC;
use crate::nft_expr::run::count::limit_cost;
use crate::nft_expr::run::run_rule_ctx;
use crate::nft_expr::stateful::{ExprStates, QuotaState};
use crate::nft_expr::uapi::*;
use super::fixture::{self, Ct};

const SEC: u64 = NSEC_PER_SEC;

/// Ten packets a second, bucket depth five.
fn pkt_limit(invert: bool) -> Expr {
    let rate = 10u64;
    let burst = 5u32;
    Expr::Limit { index: 0, limit_type: NFT_LIMIT_PKTS, rate, nsecs: SEC, burst,
                  tokens_max: (SEC / rate) * burst as u64, invert }
}

fn drive(exprs: &[Expr], states: &ExprStates, len: usize, now_ns: u64) -> i32 {
    let pkt = alloc::vec![0u8; len];
    let mut ctx = EvalCtx::ipv4(&pkt, states);
    ctx.now_ns = now_ns;
    run_rule_ctx(exprs, &mut ctx).code
}

#[test]
fn a_packet_rate_charges_the_same_for_every_packet() {
    assert_eq!(limit_cost(NFT_LIMIT_PKTS, SEC, 10, 64), SEC / 10);
    assert_eq!(limit_cost(NFT_LIMIT_PKTS, SEC, 10, 1500), SEC / 10,
        "size must not change a packet rate's cost");
}

#[test]
fn a_byte_rate_charges_by_size() {
    // A thousand bytes a second: a 100-byte packet costs a tenth of a second.
    assert_eq!(limit_cost(NFT_LIMIT_PKT_BYTES, SEC, 1000, 100), SEC / 10);
    assert_eq!(limit_cost(NFT_LIMIT_PKT_BYTES, SEC, 1000, 200), SEC / 5);
}

#[test]
fn the_bucket_starts_full_and_empties_at_the_burst_depth() {
    let exprs = vec![pkt_limit(false)];
    let states = ExprStates::for_exprs(&exprs);
    // Five packets at the same instant fit the burst; the sixth does not.
    for i in 0..5 {
        assert_eq!(drive(&exprs, &states, 64, 0), NFT_CONTINUE, "packet {i} is within burst");
    }
    assert_eq!(drive(&exprs, &states, 64, 0), NFT_BREAK,
        "the burst is spent and the rule must stop matching");
}

#[test]
fn the_bucket_refills_with_time() {
    let exprs = vec![pkt_limit(false)];
    let states = ExprStates::for_exprs(&exprs);
    for _ in 0..5 { drive(&exprs, &states, 64, 0); }
    assert_eq!(drive(&exprs, &states, 64, 0), NFT_BREAK);
    // One tenth of a second buys exactly one packet back.
    assert_eq!(drive(&exprs, &states, 64, SEC / 10), NFT_CONTINUE);
    assert_eq!(drive(&exprs, &states, 64, SEC / 10), NFT_BREAK);
}

#[test]
fn refill_is_capped_at_the_bucket_depth() {
    let exprs = vec![pkt_limit(false)];
    let states = ExprStates::for_exprs(&exprs);
    // An hour of idleness must not buy an hour's worth of burst.
    for _ in 0..5 { drive(&exprs, &states, 64, 0); }
    let far = 3600 * SEC;
    for i in 0..5 {
        assert_eq!(drive(&exprs, &states, 64, far), NFT_CONTINUE, "refilled packet {i}");
    }
    assert_eq!(drive(&exprs, &states, 64, far), NFT_BREAK,
        "idle time may not accumulate beyond the burst");
}

#[test]
fn inverting_a_limit_matches_only_the_excess() {
    let exprs = vec![pkt_limit(true)];
    let states = ExprStates::for_exprs(&exprs);
    for _ in 0..5 {
        assert_eq!(drive(&exprs, &states, 64, 0), NFT_BREAK, "within the rate, so no match");
    }
    assert_eq!(drive(&exprs, &states, 64, 0), NFT_CONTINUE, "over the rate, so it matches");
}

#[test]
fn a_byte_limit_lets_small_packets_through_where_a_large_one_does_not() {
    // One thousand bytes a second, depth one second.
    let rate = 1000u64;
    let exprs = vec![Expr::Limit { index: 0, limit_type: NFT_LIMIT_PKT_BYTES, rate,
        nsecs: SEC, burst: 0, tokens_max: SEC, invert: false }];
    let states = ExprStates::for_exprs(&exprs);
    for _ in 0..10 {
        assert_eq!(drive(&exprs, &states, 100, 0), NFT_CONTINUE);
    }
    assert_eq!(drive(&exprs, &states, 100, 0), NFT_BREAK, "the second's worth is spent");
}

#[test]
fn a_missing_state_slot_breaks_rather_than_allowing() {
    // A limit whose state was never allocated cannot know whether the budget
    // is spent; treating that as "under the limit" would disable the rule.
    let exprs = vec![pkt_limit(false)];
    let empty = ExprStates::empty();
    assert_eq!(drive(&exprs, &empty, 64, 0), NFT_BREAK);
}

#[test]
fn a_quota_is_not_over_at_exactly_its_boundary() {
    // The off-by-one that would let one extra packet through, or refuse one
    // that fits. Consumed == quota is still within budget.
    let q = QuotaState::new();
    let charge = q.consume(100, 100);
    assert!(!charge.over, "the packet that exactly fills the quota is within it");
    assert!(charge.report, "but it is the one that reports depletion");
    let next = q.consume(1, 100);
    assert!(next.over);
}

#[test]
fn a_quota_stops_matching_once_it_is_spent() {
    let exprs = vec![Expr::Quota { index: 0, quota: 250, consumed: 0, invert: false }];
    let states = ExprStates::for_exprs(&exprs);
    assert_eq!(drive(&exprs, &states, 100, 0), NFT_CONTINUE);
    assert_eq!(drive(&exprs, &states, 100, 0), NFT_CONTINUE);
    // 300 consumed against 250 allowed.
    assert_eq!(drive(&exprs, &states, 100, 0), NFT_BREAK);
    // And it stays spent.
    assert_eq!(drive(&exprs, &states, 1, 0), NFT_BREAK);
}

#[test]
fn an_inverted_quota_matches_only_the_overflow() {
    let exprs = vec![Expr::Quota { index: 0, quota: 150, consumed: 0, invert: true }];
    let states = ExprStates::for_exprs(&exprs);
    assert_eq!(drive(&exprs, &states, 100, 0), NFT_BREAK);
    assert_eq!(drive(&exprs, &states, 100, 0), NFT_CONTINUE);
}

#[test]
fn a_preset_consumption_is_honoured() {
    // A quota restored from a dump must resume where it left off, not from
    // zero, or a reload silently grants the whole budget again.
    let exprs = vec![Expr::Quota { index: 0, quota: 100, consumed: 95, invert: false }];
    let states = ExprStates::for_exprs(&exprs);
    assert_eq!(states.quotas[0].consumed(), 95);
    assert_eq!(drive(&exprs, &states, 10, 0), NFT_BREAK);
}

#[test]
fn depletion_is_reported_once() {
    let q = QuotaState::new();
    q.consume(100, 100);
    assert!(q.latch_depleted(), "first crossing reports");
    assert!(!q.latch_depleted(), "and never again");
}

#[test]
fn a_connection_limit_stops_matching_above_its_count() {
    let over = Ct { attached: true, connlimit: Some(11), ..Ct::default() };
    let at = Ct { attached: true, connlimit: Some(10), ..Ct::default() };
    let exprs = vec![Expr::Connlimit { index: 0, count: 10, invert: false }];
    let states = ExprStates::for_exprs(&exprs);
    let pkt = fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &[]);

    let mut ctx = EvalCtx::ipv4(&pkt, &states);
    ctx.ct = Some(&at);
    assert_eq!(run_rule_ctx(&exprs, &mut ctx).code, NFT_CONTINUE,
        "exactly at the limit is still within it");

    let mut ctx = EvalCtx::ipv4(&pkt, &states);
    ctx.ct = Some(&over);
    assert_eq!(run_rule_ctx(&exprs, &mut ctx).code, NFT_BREAK);
}

#[test]
fn a_connection_that_cannot_be_counted_is_dropped_not_allowed() {
    // If the flow cannot be added to the list the limit is unenforceable;
    // letting it through would make the limit advisory.
    let unknown = Ct { attached: true, connlimit: None, ..Ct::default() };
    let exprs = vec![Expr::Connlimit { index: 0, count: 10, invert: false }];
    let states = ExprStates::for_exprs(&exprs);
    let pkt = fixture::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &[]);
    let mut ctx = EvalCtx::ipv4(&pkt, &states);
    ctx.ct = Some(&unknown);
    assert_eq!(run_rule_ctx(&exprs, &mut ctx).code, NF_DROP);
}

#[test]
fn a_connection_limit_without_conntrack_breaks() {
    let exprs = vec![Expr::Connlimit { index: 0, count: 10, invert: false }];
    let states = ExprStates::for_exprs(&exprs);
    assert_eq!(drive(&exprs, &states, 64, 0), NFT_BREAK);
}

#[test]
fn last_records_the_hit_and_changes_nothing() {
    let exprs = vec![Expr::Last { index: 0, set: false, msecs: 0 }];
    let states = ExprStates::for_exprs(&exprs);
    assert_eq!(states.lasts[0].last(), None, "a never-fired expression reports unset");
    assert_eq!(drive(&exprs, &states, 64, 5 * SEC), NFT_CONTINUE);
    assert_eq!(states.lasts[0].last(), Some(5_000), "milliseconds since the clock's origin");
    drive(&exprs, &states, 64, 9 * SEC);
    assert_eq!(states.lasts[0].last(), Some(9_000), "and it moves with each hit");
}

#[test]
fn the_incremental_generator_starts_at_zero_and_wraps_at_the_modulus() {
    let exprs = vec![
        Expr::Numgen { index: 0, dreg: NFT_REG_1, modulus: 3, offset: 0,
                       ng_type: NFT_NG_INCREMENTAL },
    ];
    let states = ExprStates::for_exprs(&exprs);
    let pkt = alloc::vec![0u8; 20];
    let mut seen = alloc::vec::Vec::new();
    for _ in 0..7 {
        let mut ctx = EvalCtx::ipv4(&pkt, &states);
        let mut regs = crate::nft_expr::regs::Regs::new();
        crate::nft_expr::run::walk::run_rule_regs(&exprs, &mut ctx, &mut regs);
        seen.push(u32::from_ne_bytes(regs.load(NFT_REG_1, 4).unwrap().try_into().unwrap()));
    }
    assert_eq!(seen, alloc::vec![0, 1, 2, 0, 1, 2, 0]);
}

#[test]
fn a_generator_offset_shifts_the_whole_span() {
    let exprs = vec![
        Expr::Numgen { index: 0, dreg: NFT_REG_1, modulus: 2, offset: 100,
                       ng_type: NFT_NG_INCREMENTAL },
    ];
    let states = ExprStates::for_exprs(&exprs);
    let pkt = alloc::vec![0u8; 20];
    let mut seen = alloc::vec::Vec::new();
    for _ in 0..4 {
        let mut ctx = EvalCtx::ipv4(&pkt, &states);
        let mut regs = crate::nft_expr::regs::Regs::new();
        crate::nft_expr::run::walk::run_rule_regs(&exprs, &mut ctx, &mut regs);
        seen.push(u32::from_ne_bytes(regs.load(NFT_REG_1, 4).unwrap().try_into().unwrap()));
    }
    assert_eq!(seen, alloc::vec![100, 101, 100, 101]);
}

#[test]
fn the_random_generator_stays_inside_its_span() {
    let exprs = vec![
        Expr::Numgen { index: 0, dreg: NFT_REG_1, modulus: 7, offset: 20,
                       ng_type: NFT_NG_RANDOM },
    ];
    let states = ExprStates::for_exprs(&exprs);
    let pkt = alloc::vec![0u8; 20];
    for r in [0u32, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
        let mut ctx = EvalCtx::ipv4(&pkt, &states);
        ctx.random = r;
        let mut regs = crate::nft_expr::regs::Regs::new();
        crate::nft_expr::run::walk::run_rule_regs(&exprs, &mut ctx, &mut regs);
        let v = u32::from_ne_bytes(regs.load(NFT_REG_1, 4).unwrap().try_into().unwrap());
        assert!((20..27).contains(&v), "random {r} produced {v}");
    }
}
