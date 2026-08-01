//! E-EDID base-block decoding.
//!
//! Module manifest:
//!   `layout`      — byte offsets, sizes, and bit masks of the base block.
//!   `block`       — block validity (header, checksum) and preferred-timing policy.
//!   `dtd`         — detailed timing descriptor decode and mode construction.
//!   `established` — the standard's established-timing bitmap and its modes.
//!   `standard`    — the eight standard timing entries (size plus refresh rate).
//!   `modes`       — every mode the block publishes, ranked and deduplicated.
//!
//! A monitor's EDID reaches us as an opaque blob from the display device. This
//! module decides only what the standard states; which of those modes a
//! connector then offers is `std_modes`' decision.

mod block;
mod dtd;
mod established;
mod layout;
mod modes;
mod standard;

#[cfg(test)]
pub(crate) mod tests;

pub use block::{
    base_block, checksum_is_valid, computed_checksum, descriptor, first_detailed_is_preferred,
    header_is_valid, header_score, is_valid, revision, version,
};
pub use dtd::{decode, is_timing, preferred_mode, vrefresh, Timing};
pub use established::{bits as established_bits, modes as established_modes};
pub use layout::{
    BLOCK_LEN, DTD_COUNT, DTD_LEN, EST_TIMING_COUNT, FEATURE_PREFERRED_TIMING, HEADER, MIN_ACTIVE,
    OFF_CHECKSUM, OFF_DETAILED, OFF_ESTABLISHED, OFF_FEATURES, OFF_REVISION, OFF_STANDARD,
    OFF_VERSION, STD_TIMING_COUNT, STD_TIMING_LEN,
};
pub use modes::{all as all_modes, detailed as detailed_modes};
pub use standard::{
    modes as standard_modes, refresh_of as standard_refresh, size_of as standard_size,
};
