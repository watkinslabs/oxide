//! The TTY binding: a `/dev/rfcommN` node backed by a DLC.
//!
//! Module manifest:
//! - `dev`: the device registry, its identifiers and its lifetime bits.
//! - `ioctl`: the create/release/list/info operations and their struct codecs.
//! - `modem`: translation between the V.24 signal byte and the terminal's
//!   modem bits, in both directions.

pub mod dev;
pub mod ioctl;
pub mod modem;

pub use dev::{DevInfo, DevList, DevReq, RfcommDev};
pub use ioctl::{CreateCtx, DevIoctl};
