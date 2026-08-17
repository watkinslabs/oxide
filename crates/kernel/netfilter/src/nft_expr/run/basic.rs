//! Evaluation of the register-and-packet expressions.

extern crate alloc;
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::nft_expr::action::Action;
use crate::nft_expr::ctx::EvalCtx;
use crate::nft_expr::hashing::{jhash, reciprocal_scale};
use crate::nft_expr::limits::REG_BYTES;
use crate::nft_expr::regs::Regs;
use crate::nft_expr::run::packet::base_slice;
use crate::nft_expr::uapi::*;

/// Break the rule: the packet does not match, or the input is absent.
const BREAK: Option<i32> = Some(NFT_BREAK);

/// # C: O(1)
fn stored(result: Option<()>) -> Option<i32> { if result.is_some() { None } else { BREAK } }

/// # C: O(len)
pub fn payload(ctx: &mut EvalCtx, regs: &mut Regs, dreg: u32, base: u32, offset: u32,
                len: u32, sreg: Option<u32>, csum_type: u32, csum_offset: u32,
                csum_flags: u32) -> Option<i32>
{
    let (offset, len) = (offset as usize, len as usize);
    if let Some(sreg) = sreg {
        let data = regs.load(sreg, len)?.to_vec();
        ctx.actions.push(Action::PayloadSet { base, offset: offset as u32, data, csum_type,
                                              csum_offset, csum_flags });
        return None;
    }
    let Some(slice) = base_slice(ctx, base) else { return BREAK };
    let Some(bytes) = slice.get(offset..offset + len) else { return BREAK };
    let mut copy = [0u8; REG_BYTES];
    copy[..len].copy_from_slice(bytes);
    stored(regs.store_padded(dreg, &copy[..len]))
}

/// # C: O(len(data))
pub fn cmp(regs: &Regs, sreg: u32, op: u32, data: &[u8]) -> Option<i32> {
    let Some(actual) = regs.load(sreg, data.len()) else { return BREAK };
    let ordering = actual.cmp(data);
    let matched = match op {
        NFT_CMP_EQ  => ordering == Ordering::Equal,
        NFT_CMP_NEQ => ordering != Ordering::Equal,
        NFT_CMP_LT  => ordering == Ordering::Less,
        NFT_CMP_LTE => ordering != Ordering::Greater,
        NFT_CMP_GT  => ordering == Ordering::Greater,
        NFT_CMP_GTE => ordering != Ordering::Less,
        _ => false,
    };
    if matched { None } else { BREAK }
}

/// # C: O(len(from))
pub fn range(regs: &Regs, sreg: u32, op: u32, from: &[u8], to: &[u8]) -> Option<i32> {
    let Some(actual) = regs.load(sreg, from.len()) else { return BREAK };
    let below = actual.cmp(from) == Ordering::Less;
    let above = actual.cmp(to) == Ordering::Greater;
    let inside = !below && !above;
    match op {
        NFT_RANGE_EQ  => if inside { None } else { BREAK },
        NFT_RANGE_NEQ => if inside { BREAK } else { None },
        _ => BREAK,
    }
}

/// # C: O(len(value))
pub fn immediate(regs: &mut Regs, dreg: u32, verdict: Option<i32>, value: &[u8])
    -> Option<i32>
{
    if dreg == NFT_REG_VERDICT { return verdict.or(BREAK); }
    stored(regs.store(dreg, value))
}

/// # C: O(len)
pub fn bitwise(regs: &mut Regs, sreg: u32, dreg: u32, mask: &[u8], xor: &[u8])
    -> Option<i32>
{
    let mut scratch = [0u8; REG_BYTES];
    let Some(src) = regs.load(sreg, mask.len()) else { return BREAK };
    for (i, slot) in scratch[..mask.len()].iter_mut().enumerate() {
        *slot = (src[i] & mask[i]) ^ xor[i];
    }
    stored(regs.store(dreg, &scratch[..mask.len()]))
}

/// # C: O(len)
pub fn byteorder(regs: &mut Regs, sreg: u32, dreg: u32, len: u32, size: u32)
    -> Option<i32>
{
    let (len, size) = (len as usize, size as usize);
    let mut scratch = [0u8; REG_BYTES];
    let Some(src) = regs.load(sreg, len) else { return BREAK };
    for (out, chunk) in scratch[..len].chunks_mut(size).zip(src.chunks(size)) {
        for (slot, &byte) in out.iter_mut().zip(chunk.iter().rev()) { *slot = byte; }
    }
    stored(regs.store(dreg, &scratch[..len]))
}

/// # C: O(cost of the set lookup)
pub fn lookup(ctx: &EvalCtx, regs: &Regs, sreg: u32, set: &str, set_id: Option<usize>,
              invert: bool) -> Option<i32>
{
    let Some(key) = regs.tail(sreg) else { return BREAK };
    let hit = match ctx.set_lookup { Some(f) => f(set_id, set, key), None => false };
    if hit ^ invert { None } else { BREAK }
}

/// # C: O(len)
pub fn hash(ctx: &EvalCtx, regs: &mut Regs, sreg: u32, dreg: u32, len: u32, modulus: u32,
            seed: u32, offset: u32, hash_type: u32) -> Option<i32>
{
    let raw = match hash_type {
        NFT_HASH_SYM => {
            // A symmetric hash mixes the flow both ways round so the two
            // directions land together; without the flow it cannot be formed.
            let Some(ct) = ctx.ct else { return BREAK };
            let Some(tuple) = ct.tuple(conntrack::uapi::IP_CT_DIR_ORIGINAL) else {
                return BREAK;
            };
            conntrack::hash::src_hash(&tuple, seed)
        }
        _ => {
            let Some(src) = regs.load(sreg, len as usize) else { return BREAK };
            jhash(src, seed)
        }
    };
    stored(regs.store_u32(dreg, reciprocal_scale(raw, modulus) + offset))
}

/// # C: O(1)
pub fn numgen(ctx: &EvalCtx, regs: &mut Regs, index: usize, dreg: u32, modulus: u32,
              offset: u32, ng_type: u32) -> Option<i32>
{
    let value = match ng_type {
        NFT_NG_INCREMENTAL => {
            let Some(state) = ctx.states.numgens.get(index) else { return BREAK };
            state.next(modulus)
        }
        _ => reciprocal_scale(ctx.random, modulus),
    };
    stored(regs.store_u32(dreg, value + offset))
}

/// Registers a rule reads from a set, for the store's key-width check.
/// # C: O(N exprs)
pub fn lookup_registers(exprs: &[crate::nft_expr::expr::Expr]) -> Vec<(u32, &str)> {
    use crate::nft_expr::expr::Expr;
    exprs.iter().filter_map(|e| match e {
        Expr::Lookup { sreg, set, .. } => Some((*sreg, set.as_str())),
        _ => None,
    }).collect()
}
