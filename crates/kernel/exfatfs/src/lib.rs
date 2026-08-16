#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! exFAT: what large removable media are formatted with.
//!
//! FAT cannot hold a file over four gigabytes and cannot address a volume much
//! past two terabytes, so every camera card, every large USB stick and every
//! external drive sold for use between machines is exFAT. Without it those
//! media do not mount at all.
//!
//! Two things make it a different filesystem from FAT rather than a wider one,
//! and both reach everything above them:
//!
//! - **Allocation is the BITMAP, not the table.** A run may be recorded as
//!   contiguous with no table entries at all, so every one of its clusters
//!   reads as free from the table. Allocating from the table hands out
//!   clusters that are already in use.
//! - **A name is a SET of entries**, not one record, and the set carries a
//!   checksum over all of them. Writing one entry of a set without resealing
//!   it leaves a set every other implementation rejects.
//!
//! Module manifest:
//! - `uapi`:     the on-disk numbers the format is defined in terms of.
//! - `checksum`: the three rotate-and-add sums, and what each skips.
//! - `boot`:     the boot sector, and what tells exFAT from FAT.
//! - `geometry`: where everything lives, once the fields are resolved.
//! - `chain`:    a run of clusters, and the two ways one is recorded.
//! - `fat`:      the allocation table, held whole and mirrored on write.
//! - `bitmap`:   which clusters are free — the only truth about that.
//! - `upcase`:   the volume's own answer to which two names are the same.
//! - `name`:     UTF-16 on the medium, UTF-8 at the interface, and the hash.
//! - `time`:     the stored pair, plus the UTC offset carried beside it.
//! - `dirent`:   entries, and the sets they come in.
//! - `attrs`:    the attribute word, and the mode an entry presents as.
//! - `ident`:    what an inode number is on a filesystem that stores none.
//! - `opts`:     what a mount was asked for, and what it reports back.
//! - `volume`:   a mounted volume, driven against a real medium.
//! - `mount`:    the VFS-facing filesystem, its inodes and their operations.

extern crate alloc;

pub mod uapi;
pub mod checksum;
pub mod boot;
pub mod geometry;
pub mod chain;
pub mod fat;
pub mod bitmap;
pub mod upcase;
pub mod name;
pub mod time;
pub mod dirent;
pub mod attrs;
pub mod ident;
pub mod opts;
pub mod volume;
pub mod mount;

pub use boot::{Boot, BootError};
pub use chain::Chain;
pub use dirent::{EntrySet, FileEntry, StreamEntry};
pub use geometry::Geometry;
pub use mount::{ExfatFs, EXFAT_NAME};
pub use opts::{Options, EXFAT_NAME_MAX};
pub use uapi::EXFAT_SUPER_MAGIC;
pub use upcase::UpCase;
pub use volume::{DirEntry, DirHandle, Volume};

/// The boot sector every test volume starts from, shared so one layout change
/// does not have to be made in a dozen fixtures. # C: O(1)
#[cfg(test)]
pub(crate) fn tests_boot_sector() -> alloc::vec::Vec<u8> { boot::tests::sector() }

/// The image builder every volume-level test drives. # C: see `tests/image.rs`
#[cfg(test)]
#[path = "tests/image.rs"]
pub(crate) mod test_image;
