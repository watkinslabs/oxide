//! Management-interface wire constants.
//!
//! Module manifest:
//! - `limits`: header width, index sentinel, protocol version, name and struct
//!   widths every fixed-size record is measured against.
//! - `status`: the management status byte userspace reads out of every command
//!   status and command complete.
//! - `op`: command opcodes together with the parameter width each declares.
//! - `ev`: event codes and the enumerations events carry.
//! - `flags`: settings bits, advertising flags, PHY bits, device flags,
//!   discovery types and every other bitmask the interface exchanges.

pub mod limits;
pub mod status;
pub mod op;
pub mod ev;
pub mod flags;
