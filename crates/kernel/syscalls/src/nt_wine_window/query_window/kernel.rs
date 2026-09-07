//! Kernel routing: the canonical window, thread and input-context owners
//! answer each window-info class.
use super::*;
use crate::nt_window::imc;

/// # C: O(processes + windows)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if ordinal != ORDINAL { return None; }
    let (hwnd, cls) = (args.first().copied().unwrap_or(0), args.get(1).copied().unwrap_or(0));
    Some(answer(cls, imc::query_window_facts(hwnd, cls, timekeeper::monotonic_ns())))
}
