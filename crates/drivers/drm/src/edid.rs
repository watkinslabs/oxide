//! E-EDID base-block decoding.
//!
//! Module manifest:
//!   `layout` — byte offsets, sizes, and bit masks of the base block.
//!   `block`  — block validity (header, checksum) and preferred-timing policy.
//!   `dtd`    — detailed timing descriptor decode and mode construction.
//!
//! A monitor's EDID reaches us as an opaque blob from the display device. This
//! module decides only what the standard states; which mode a connector then
//! offers is `std_modes`' decision.

mod block;
mod dtd;
mod layout;

#[cfg(test)]
mod tests;

pub use block::{
    base_block, checksum_is_valid, computed_checksum, descriptor, first_detailed_is_preferred,
    header_is_valid, header_score, is_valid, revision, version,
};
pub use dtd::{decode, is_timing, preferred_mode, vrefresh, Timing};
pub use layout::{BLOCK_LEN, DTD_COUNT, DTD_LEN, HEADER, MIN_ACTIVE, OFF_DETAILED};
