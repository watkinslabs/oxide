//! Fixed-shape entry points: a rule walk over a bare packet with no
//! subsystem lookups, reporting only the absolute verdict.

use crate::nft_expr::ctx::{EvalCtx, SetLookupFn};
use crate::nft_expr::expr::Expr;
use crate::nft_expr::stateful::ExprStates;
use crate::nft_expr::uapi::NFPROTO_IPV4;
use crate::nft_expr::run::walk::run_rule_ctx;

/// Walk a rule with no set lookups. # C: O(N exprs × expression cost)
pub fn run_rule(exprs: &[Expr], pkt: &[u8]) -> Option<i32> {
    run_rule_with_lookup(exprs, pkt, None)
}

/// # C: O(N exprs × expression cost)
pub fn run_rule_with_lookup(exprs: &[Expr], pkt: &[u8], lookup: Option<SetLookupFn>)
    -> Option<i32>
{
    let (mut packets, mut bytes) = (0u64, 0u64);
    run_rule_full(exprs, pkt, lookup, NFPROTO_IPV4, &mut packets, &mut bytes)
}

/// Same, accumulating the counters every `counter` expression the walk
/// reaches. A rule that breaks before one never reaches it, which is what
/// makes counter placement meaningful. # C: O(N exprs × expression cost)
pub fn run_rule_full(exprs: &[Expr], pkt: &[u8], lookup: Option<SetLookupFn>, family: u8,
                     packets: &mut u64, bytes: &mut u64) -> Option<i32>
{
    let mut mark = 0;
    run_rule_full_with_mark(exprs, pkt, lookup, family, &mut mark, packets, bytes)
}

/// Same, carrying the packet mark in and out so it survives across rules.
/// # C: O(N exprs × expression cost)
pub fn run_rule_full_with_mark(exprs: &[Expr], pkt: &[u8], lookup: Option<SetLookupFn>,
                               family: u8, mark: &mut u32, packets: &mut u64,
                               bytes: &mut u64) -> Option<i32>
{
    let states = ExprStates::for_exprs(exprs);
    let mut ctx = EvalCtx::new(pkt, family, &states);
    ctx.mark = *mark;
    ctx.set_lookup = lookup;
    let verdict = run_rule_ctx(exprs, &mut ctx);
    *mark = ctx.mark;
    *packets += ctx.packets;
    *bytes += ctx.bytes;
    verdict.is_absolute().then_some(verdict.code)
}
