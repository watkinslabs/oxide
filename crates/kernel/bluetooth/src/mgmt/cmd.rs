//! Command request payloads.
//!
//! Module manifest:
//! - `simple`: the mode byte and the small fixed-shape setters — class, name,
//!   identity, scan parameters, appearance, PHY selection, UUID list.
//! - `keys`: the load commands and the out-of-band data commands, every one of
//!   them a count followed by that many fixed-width records.
//! - `pairing`: bonding and the reply commands that answer a pairing prompt.
//! - `device`: the device list, its per-device flags, and the two info reads.
//! - `adv`: advertising instances, extended advertising, monitors, mesh, and
//!   the pass-through command.
//!
//! Every decoder refuses a payload that is short OR long: a trailing byte means
//! the sender and this stack disagree about the record, and guessing which of
//! the two is right is how a field silently shifts.

pub mod simple;
pub mod keys;
pub mod pairing;
pub mod device;
pub mod adv;
