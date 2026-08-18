//! Built-in device-mapper target manifest.
//!
//! - `linear`: one contiguous backing-device range.
//! - `stripe`: round-robin chunks over backing devices.
//! - `trivial`: zero, error, and delay test/control targets.
//! - `crypt`: sector encryption target parsing and mapping.

pub mod crypt;
pub mod linear;
pub mod stripe;
pub mod trivial;

pub use trivial::{delay, error, zero};
