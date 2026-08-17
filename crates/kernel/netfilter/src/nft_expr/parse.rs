//! Wire-to-expression decoding.
//!
//! Module manifest:
//! - `state_alloc`: index assignment for stateful expressions.
//! - `basic`: register-and-packet expressions.
//! - `conn`: connection-tracking and translation expressions.
//! - `misc`: rate, accounting, logging, header-option and lookup expressions.
//! - `dispatch`: name dispatch over one rule's expression list.

pub mod state_alloc;
pub mod basic;
pub mod conn;
pub mod misc;
pub mod dispatch;

pub use state_alloc::StateAlloc;
pub use dispatch::{parse_exprs, parse_exprs_checked, parse_exprs_in, parse_one_expr};
