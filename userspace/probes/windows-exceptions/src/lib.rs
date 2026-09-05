//! Windows exception-code classification and dispatch ordering probe.
//!
//! The decision is deliberately pure: the native exception owner supplies the
//! two handler results, while this crate checks the ABI-visible ordering.

mod dispatch;

pub use dispatch::{classify, dispatch, ExceptionClass, HandlerResult, Outcome};
