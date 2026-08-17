//! What went wrong with this volume, written where the next tool can read it.
//!
//! The superblock carries two arrays nothing else does: a bitmap of the
//! inconsistency KINDS this volume has ever shown, and a per-reason count of
//! the times a mount stopped checkpointing. Both outlive the mount, and that is
//! the point — a filesystem that is repaired, remounted and repaired again
//! looks identical to a healthy one from a fresh mount, and the arrays are the
//! only record that says otherwise. A checker reads them to decide how hard to
//! look; a fleet operator reads them to tell a bad batch of devices from a bad
//! release.
//!
//! Nothing here is clever, and everything here is easy to get silently wrong:
//! an array that is filled in memory and never written reads exactly like a
//! volume that has never had a problem.
//!
//! Module manifest:
//! - `uapi`:   the two enumerations, and the widths their arrays have.
//! - `record`: the arrays in memory, what dirties them, and the bytes they
//!             become.
//! - `handle`: what a mount does when it finds something wrong.

pub mod uapi;
pub mod record;
pub mod handle;

pub use record::ErrorRecord;
pub use uapi::{Error, StopReason};
