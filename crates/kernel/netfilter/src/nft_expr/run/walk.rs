//! The rule walk: run each expression in order until one sets a verdict.

extern crate alloc;

use crate::nft_expr::ctx::EvalCtx;
use crate::nft_expr::expr::Expr;
use crate::nft_expr::regs::Regs;
use crate::nft_expr::run::{action, basic, count, ct, meta, source};
use crate::nft_expr::uapi::{NFT_BREAK, NFT_REG_VERDICT};
use crate::nft_expr::verdict::RuleVerdict;

const BREAK: Option<i32> = Some(NFT_BREAK);

/// Evaluate one expression. `None` means fall through to the next one.
/// # C: O(expression cost)
fn step(expr: &Expr, ctx: &mut EvalCtx, regs: &mut Regs) -> Option<i32> {
    match expr {
        Expr::Payload { dreg, base, offset, len, sreg, csum_type, csum_offset, csum_flags } =>
            basic::payload(ctx, regs, *dreg, *base, *offset, *len, *sreg, *csum_type,
                           *csum_offset, *csum_flags),
        Expr::Cmp { sreg, op, data } => basic::cmp(regs, *sreg, *op, data),
        Expr::Range { sreg, op, from, to } => basic::range(regs, *sreg, *op, from, to),
        Expr::Immediate { dreg, verdict, value, .. } =>
            basic::immediate(regs, *dreg, *verdict, value),
        Expr::Bitwise { sreg, dreg, mask, xor } => basic::bitwise(regs, *sreg, *dreg, mask, xor),
        Expr::Byteorder { sreg, dreg, len, size, .. } =>
            basic::byteorder(regs, *sreg, *dreg, *len, *size),
        Expr::Lookup { sreg, set, set_id, invert, .. } =>
            basic::lookup(ctx, regs, *sreg, set, *set_id, *invert),
        Expr::Hash { sreg, dreg, len, modulus, seed, offset, hash_type } =>
            basic::hash(ctx, regs, *sreg, *dreg, *len, *modulus, *seed, *offset, *hash_type),
        Expr::Numgen { index, dreg, modulus, offset, ng_type } =>
            basic::numgen(ctx, regs, *index, *dreg, *modulus, *offset, *ng_type),
        Expr::Counter => {
            ctx.packets = ctx.packets.wrapping_add(1);
            ctx.bytes = ctx.bytes.wrapping_add(ctx.pkt.len() as u64);
            None
        }
        Expr::Notrack => { ctx.notrack = true; None }

        Expr::Meta { dreg, sreg, key } => match (dreg, sreg) {
            (Some(dreg), _) => meta::get(ctx, regs, *dreg, *key),
            (_, Some(sreg)) => meta::set(ctx, regs, *sreg, *key),
            _ => BREAK,
        },
        Expr::Ct { dreg, sreg, key, dir, len } => match (dreg, sreg) {
            (Some(dreg), _) => ct::get(ctx, regs, *dreg, *key, *dir, *len),
            (_, Some(sreg)) => ct::set(ctx, regs, *sreg, *key, *len),
            _ => BREAK,
        },

        Expr::Nat { nat_type, family, flags, sreg_addr_min, sreg_addr_max, sreg_proto_min,
                    sreg_proto_max } =>
            action::nat(ctx, regs, *nat_type, *family, *flags, *sreg_addr_min, *sreg_addr_max,
                        *sreg_proto_min, *sreg_proto_max),
        Expr::Masq { flags, sreg_proto_min, sreg_proto_max } =>
            action::masq(ctx, regs, *flags, *sreg_proto_min, *sreg_proto_max),
        Expr::Redir { flags, sreg_proto_min, sreg_proto_max } =>
            action::redir(ctx, regs, *flags, *sreg_proto_min, *sreg_proto_max),
        Expr::Dup { sreg_addr, sreg_dev } => action::dup(ctx, regs, *sreg_addr, *sreg_dev),
        Expr::Fwd { sreg_dev, sreg_addr, nfproto } =>
            action::fwd(ctx, regs, *sreg_dev, *sreg_addr, *nfproto),
        Expr::Log { group, level, prefix, snaplen, qthreshold, flags } =>
            action::log(ctx, *group, *level, prefix, *snaplen, *qthreshold, *flags),
        Expr::Reject { reject_type, icmp_code } => action::reject(ctx, *reject_type, *icmp_code),
        Expr::Queue { num, total, flags, sreg_qnum } =>
            action::queue(ctx, regs, *num, *total, *flags, *sreg_qnum),
        Expr::Tproxy { family, sreg_addr, sreg_port } =>
            action::tproxy(ctx, regs, *family, *sreg_addr, *sreg_port),
        Expr::Synproxy { mss, wscale, flags } => action::synproxy(ctx, *mss, *wscale, *flags),
        Expr::FlowOffload { table } => action::flow_offload(ctx, table),

        Expr::Limit { index, limit_type, rate, nsecs, tokens_max, invert, .. } =>
            count::limit(ctx, *index, *limit_type, *rate, *nsecs, *tokens_max, *invert),
        Expr::Quota { index, quota, invert, .. } => count::quota(ctx, *index, *quota, *invert),
        Expr::Connlimit { index, count: limit, invert } =>
            count::connlimit(ctx, *index, *limit, *invert),
        Expr::Last { index, .. } => count::last(ctx, *index),

        Expr::Rt { dreg, key } => source::rt(ctx, regs, *dreg, *key),
        Expr::Fib { dreg, result, flags } => source::fib(ctx, regs, *dreg, *result, *flags),
        Expr::Socket { dreg, key, level } => source::socket(ctx, regs, *dreg, *key, *level),
        Expr::Osf { dreg, ttl, flags } => source::osf(ctx, regs, *dreg, *ttl, *flags),
        Expr::Xfrm { dreg, key, dir, spnum } => source::xfrm(ctx, regs, *dreg, *key, *dir, *spnum),
        Expr::Tunnel { dreg, key, mode } => source::tunnel(ctx, regs, *dreg, *key, *mode),
        Expr::Exthdr { dreg, sreg, op, htype, offset, len, flags } =>
            source::exthdr(ctx, regs, *dreg, *sreg, *op, *htype, *offset, *len, *flags),

        Expr::Objref { obj_type, name, sreg, set, set_id } => {
            let Some(objects) = ctx.objects else { return BREAK };
            match (name, sreg) {
                (Some(name), _) => objects.eval(obj_type.unwrap_or(0), name),
                (_, Some(sreg)) => {
                    let Some(key) = regs.tail(*sreg) else { return BREAK };
                    objects.eval_from_set(*set_id, set.as_deref().unwrap_or(""), key)
                }
                _ => BREAK,
            }
        }
    }
}

/// Walk one rule's expressions against `ctx`. # C: O(N exprs × expression cost)
pub fn run_rule_ctx(exprs: &[Expr], ctx: &mut EvalCtx) -> RuleVerdict {
    let mut regs = Regs::new();
    run_rule_regs(exprs, ctx, &mut regs)
}

/// Same walk over a caller-owned register file, so the bytes an expression
/// wrote can be read back without a comparison expression standing between
/// the value and the assertion.
/// # C: O(N exprs × expression cost)
pub fn run_rule_regs(exprs: &[Expr], ctx: &mut EvalCtx, regs: &mut Regs) -> RuleVerdict {
    for expr in exprs {
        let Some(code) = step(expr, ctx, regs) else { continue };
        let chain = match expr {
            Expr::Immediate { dreg, chain, .. } if *dreg == NFT_REG_VERDICT => chain.clone(),
            _ => None,
        };
        return RuleVerdict { code, chain };
    }
    RuleVerdict::cont()
}
