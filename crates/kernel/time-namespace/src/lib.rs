// Linux TIME namespace state keyed by canonical namespace identity.
//
// Module manifest:
// - `state`: offset lifecycle, validation, and host-clock conversion.
// - `tests`: focused hosted contracts for exact-owner state.

#![no_std]

extern crate alloc;

mod state;

pub use state::{absolute_to_host, absolute_to_host_or_initial, apply_display_offset, clone_from,
    freeze, set_offsets, snapshot, TimeNsClock, TimeNsError, TimeNsOffsets, TimeNsState,
    TimeNsUpdate, TimeOffset, KTIME_SEC_MAX, NSEC_PER_SEC};

#[cfg(test)]
mod tests;
