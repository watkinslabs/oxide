//! Window ordinal wiring.
//!
//! Module manifest:
//! - `tree.rs`   — tree, point, enumeration and text ordinals.
//! - `attrs.rs`  — style, attribute, foreground and record-writing ordinals.
//! - `batch.rs`  — the deferred window-position ordinals.
use super::*;

#[path = "kernel/tree.rs"]
mod tree;
#[path = "kernel/attrs.rs"]
mod attrs;
#[path = "kernel/batch.rs"]
mod batch;

pub(crate) const STATUS_SUCCESS: u64 = 0;
pub(crate) const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
pub(crate) const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
/// Error the calls that read a caller-sized record report through the TEB.
pub(crate) const ERROR_INVALID_PARAMETER: u32 = 87;
pub(crate) const ERROR_NOACCESS: u32 = 998;
pub(crate) const ERROR_INVALID_WINDOW_HANDLE: u32 = 1400;

pub(crate) fn win_bool(value: bool) -> u64 { value as u64 }

/// # C: O(window owner work plus bounded usercopy)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if !claims(ordinal) { return None; }
    tree::route(ordinal, args)
        .or_else(|| attrs::route(ordinal, args))
        .or_else(|| batch::route(ordinal, args))
        .or(Some(STATUS_INVALID_PARAMETER))
}
