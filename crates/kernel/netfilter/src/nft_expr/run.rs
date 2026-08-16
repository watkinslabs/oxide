//! Rule evaluation.
//!
//! Module manifest:
//! - `packet`: header geometry the packet-reading expressions share.
//! - `basic`: register-and-packet expressions.
//! - `meta`: the `meta` key set, both directions.
//! - `ct`: the `ct` key set, both directions.
//! - `action`: expressions that record an effect on the packet.
//! - `count`: rate, budget, connection and hit counting.
//! - `source`: route, socket, fingerprint, transform, tunnel and header
//!   options.
//! - `walk`: the expression loop.
//! - `compat`: the fixed-shape entry points older callers use.

pub mod packet;
pub mod basic;
pub mod meta;
pub mod ct;
pub mod action;
pub mod count;
pub mod source;
pub mod walk;
pub mod compat;

pub use walk::{run_rule_ctx, run_rule_regs};
pub use compat::{run_rule, run_rule_full, run_rule_full_with_mark, run_rule_with_lookup};
