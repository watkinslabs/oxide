//! Evaluation of the expressions that count: rate, budget, connections, hits.

use crate::nft_expr::ctx::EvalCtx;
use crate::nft_expr::limits::NSEC_PER_SEC;
use crate::nft_expr::uapi::{NFT_BREAK, NFT_LIMIT_PKTS};

const BREAK: Option<i32> = Some(NFT_BREAK);

/// Tokens one packet costs against a rate. A packet rate charges the same for
/// every packet; a byte rate charges by size. # C: O(1)
pub fn limit_cost(limit_type: u32, nsecs: u64, rate: u64, len: u64) -> u64 {
    if limit_type == NFT_LIMIT_PKTS { nsecs / rate } else { nsecs.saturating_mul(len) / rate }
}

/// # C: O(1)
#[allow(clippy::too_many_arguments)]
pub fn limit(ctx: &EvalCtx, index: usize, limit_type: u32, rate: u64, nsecs: u64,
             tokens_max: u64, invert: bool) -> Option<i32>
{
    let Some(state) = ctx.states.limits.get(index) else { return BREAK };
    let cost = limit_cost(limit_type, nsecs, rate, ctx.pkt_len() as u64);
    let over = state.charge(cost, tokens_max, ctx.now_ns);
    if over ^ invert { BREAK } else { None }
}

/// # C: O(1)
pub fn quota(ctx: &EvalCtx, index: usize, quota: u64, invert: bool) -> Option<i32> {
    let Some(state) = ctx.states.quotas.get(index) else { return BREAK };
    let charge = state.consume(ctx.pkt_len() as u64, quota);
    if charge.report { state.latch_depleted(); }
    if charge.over ^ invert { BREAK } else { None }
}

/// # C: O(N conns on the list)
pub fn connlimit(ctx: &EvalCtx, index: usize, count: u32, invert: bool) -> Option<i32> {
    let Some(ct) = ctx.ct else { return BREAK };
    // A flow that cannot be added to the list cannot be counted, and letting
    // it through would make the limit advisory.
    let Some(live) = ct.connlimit_count(index) else { return Some(crate::nft_expr::uapi::NF_DROP) };
    if (live > count) ^ invert { BREAK } else { None }
}

/// Records the hit and never changes the verdict. # C: O(1)
pub fn last(ctx: &EvalCtx, index: usize) -> Option<i32> {
    if let Some(state) = ctx.states.lasts.get(index) {
        state.hit(ctx.now_ns / (NSEC_PER_SEC / 1_000));
    }
    None
}
