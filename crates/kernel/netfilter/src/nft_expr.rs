//! nftables rule-expression interpreter.
//!
//! `NFTA_RULE_EXPRESSIONS` is a list of nested `NFTA_LIST_ELEM` attrs, each
//! carrying one expression: a pair of `NFTA_EXPR_NAME` (the kind) and
//! `NFTA_EXPR_DATA` (kind-specific TLVs). Parsing turns that into `Expr`;
//! evaluation walks the list against an `EvalCtx` and a register file until
//! one expression sets a verdict.
//!
//! Module manifest:
//! - `uapi`: attribute numbers, key enumerations, verdicts, register numbering.
//! - `flags`: bit flags carried in expression attributes.
//! - `limits`: sizes, counts and defaults.
//! - `nla`: netlink attribute walking.
//! - `regs`: the register file.
//! - `expr`: parsed expression forms and the parse error set.
//! - `verdict`: what one rule evaluation produced.
//! - `access`: traits for the subsystem lookups expressions need.
//! - `action`: effects an expression asks for on the packet.
//! - `ctx`: the evaluation context.
//! - `stateful`: state the counting expressions keep between packets.
//! - `hashing`: byte-oriented Jenkins hash.
//! - `parse`: wire-to-expression decoding.
//! - `validate`: load-time hook and family refusal.
//! - `run`: evaluation.

pub mod uapi;
pub mod flags;
pub mod limits;
pub mod nla;
pub mod regs;
pub mod expr;
pub mod verdict;
pub mod access;
pub mod action;
pub mod ctx;
pub mod stateful;
pub mod hashing;
pub mod parse;
pub mod validate;
pub mod run;

pub use access::{CtAccess, FibEntry, FibKey, ObjectAccess, OsfAccess, RouteAccess, SocketAccess,
                 SynproxyAccess, TunnelAccess, XfrmAccess, XfrmState};
pub use action::Action;
pub use ctx::{EvalCtx, IfInfo, PktMeta, SetLookupFn};
pub use expr::{Expr, ParseError};
pub use flags::*;
pub use limits::REG_BYTES;
pub use parse::{parse_exprs, parse_exprs_checked, parse_exprs_in};
pub use regs::{reg_off, register_load_valid, Regs};
pub use run::{run_rule, run_rule_ctx, run_rule_full, run_rule_full_with_mark,
              run_rule_regs, run_rule_with_lookup};
pub use stateful::{ExprStates, LastState, LimitState, NumgenState, QuotaCharge, QuotaState};
pub use uapi::*;
pub use validate::{validate_expr, validate_exprs};
pub use verdict::RuleVerdict;

#[cfg(test)]
#[path = "nft_expr_tests.rs"]
mod tests;
