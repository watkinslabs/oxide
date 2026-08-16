// Trusted platform module core.
//
// Module manifest:
//   uapi.rs     — wire constants: command codes, tags, response codes,
//                 algorithm ids, handles, capabilities, 1.2 ordinals
//   limits.rs   — buffer sizes, register counts, timeout/duration classes
//   flags.rs    — hardware register offsets and bit definitions, session and
//                 object attribute bits
//   alg.rs      — algorithm identity, digest width, and the one hashing call
//   rc.rs       — response-code decode, both formats
//   duration.rs — per-command duration bounds
//   pcr.rs      — register banks and the extend arithmetic
//   codec/      — command building and response parsing
//   tis.rs      — FIFO interface state machine
//   crb.rs      — control-buffer interface state machine
//   eventlog/   — TCG event log: parse and build, both formats
//   chip.rs     — character-device transaction model
//   space.rs    — resource-manager space: virtual handles, close semantics
//
// Every module here is target-independent and hosted-testable; nothing in
// this crate is compiled only for the kernel target.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

extern crate alloc;

pub mod uapi;
pub mod limits;
pub mod flags;
pub mod alg;
pub mod rc;
pub mod duration;
pub mod pcr;
pub mod codec;
pub mod tis;
pub mod crb;
pub mod eventlog;
pub mod chip;
pub mod space;

pub use alg::Alg;
pub use pcr::{AllocatedBanks, BankInfo, PcrError};
pub use rc::Rc;

#[cfg(test)]
mod tests;
