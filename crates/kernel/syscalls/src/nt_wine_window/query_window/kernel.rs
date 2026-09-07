//! Kernel routing: the canonical window, thread and input-context owners
//! answer each window-info class.
use super::*;
use crate::nt_window::imc;

/// # C: O(processes + windows)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if ordinal != ORDINAL { return None; }
    Some(answer(args[1], imc::query_window_facts(args[0], args[1], timekeeper::monotonic_ns())))
}
