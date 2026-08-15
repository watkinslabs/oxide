#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! FAT: the filesystem on every EFI system partition and almost every USB
//! stick handed between machines.
//!
//! Without it `/boot/efi` cannot be mounted on a UEFI install and no removable
//! medium formatted elsewhere can be read at all.
//!
//! Module manifest:
//! - `bpb`:      the boot sector's fields, and which of them are valid.
//! - `geometry`: where everything lives, and which FAT width this volume is.
//! - `dirent`:   the 32-byte records, and the long name spread across several.
//!
//! Both are pure functions over bytes, so the whole layout contract — the
//! validation order, the cluster-count rule that decides FAT12 from FAT16, the
//! clamp against a short table — fails a test without a disk or a mount.

extern crate alloc;

pub mod bpb;
pub mod geometry;
pub mod dirent;

pub use bpb::{Bpb, BpbError};
pub use dirent::{checksum, short_name, Entry, LongName, ShortEntry};
pub use geometry::{Geometry, GeometryError, FatWidth};
