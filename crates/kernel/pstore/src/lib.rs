//! Persistent store (Linux `fs/pstore`): a region of memory a reboot does not
//! clear, the records the kernel writes into it when it is about to stop, and
//! the filesystem that publishes each survivor as a file.
//!
//! Module manifest:
//! - `uapi`: filesystem magic, record-class names, crash reasons.
//! - `limits`: sizes, counts and bounds, each one the reference states.
//! - `zone`: one persistent-RAM zone — header, validation, circular writes.
//! - `geometry`: which physical range to reserve, and how it divides.
//! - `hdr`: the timestamp line a record carries and the parse that strips it.
//! - `record`: a captured record and its filename.
//! - `kmsg`: the `kmsg_bytes` bound and the mount parameter that sets it.
//! - `ram`: the persistent-RAM backend over a reserved region.
//! - `psinfo`: backend registration, the capture filter, and the capture.
//! - `fs`: the mount — a record per file, unlink erases.
//! - `boot`: the kernel-only half: reserve, map, attach, hook.
//!
//! Every module but `boot` is ungated: the zone geometry, header validation,
//! record enumeration and the `kmsg_bytes` bound are decisions, and a
//! decision that only exists in a kernel build is a decision no test can
//! fail on.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod fs;
pub mod geometry;
pub mod hdr;
pub mod kmsg;
pub mod limits;
pub mod psinfo;
pub mod ram;
pub mod record;
pub mod uapi;
pub mod zone;

#[cfg(target_os = "oxide-kernel")]
pub mod boot;

pub use fs::{mount, PstoreFs};
pub use kmsg::{kmsg_bytes, set_kmsg_bytes, PSTORE_PARAMS};
pub use record::{Record, RecordId};
pub use uapi::{DumpReason, RecordType, PSTOREFS_MAGIC};
