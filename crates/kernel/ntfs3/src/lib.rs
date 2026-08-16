#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! NTFS: what a disk shared with Windows is formatted as.
//!
//! Everything on this filesystem is a record in one table, and everything a
//! record IS is an attribute. There are no fields: a name is an attribute, a
//! timestamp is an attribute, the file's bytes are an attribute, and a
//! directory's contents are two attributes holding a B-tree. That uniformity
//! is what makes the format extensible and what makes a reader that guesses
//! wrong produce plausible nonsense rather than an error.
//!
//! Four things reach everything above them:
//!
//! - **The update sequence.** The last two bytes of every 512 in a record are
//!   replaced by a repeated value before it is written. A reader that does not
//!   put them back decodes a record with two bytes of every sector wrong.
//! - **Runlists are DELTAS.** A run's cluster is a signed offset from the
//!   previous run's, so reading it as absolute puts every run after the first
//!   in the wrong place; a run with no offset at all is a HOLE.
//! - **A directory is a TREE**, and its second level lives in a different
//!   attribute. Reading only the root lists the few names that fit there.
//! - **`$UpCase` decides the ORDER**, not just equality. A descent under a
//!   different fold walks to the wrong child and reports a file that is there
//!   as absent.
//!
//! Module manifest:
//! - `uapi`:         the on-disk numbers the format is defined in terms of.
//! - `fixup`:        the update sequence, both directions.
//! - `boot`:         the boot sector, and the geometry it resolves to.
//! - `record`:       an MFT record's header, and its attribute list.
//! - `attrib`:       an attribute, resident and non-resident.
//! - `run`:          the runlist codec.
//! - `lznt`:         the compression a compressed attribute holds.
//! - `upcase`:       the volume's fold, and the order its trees are in.
//! - `upcase_rules`: the built-in fold, for a volume whose own is unreadable.
//! - `name`:         `$FILE_NAME`, and the namespaces a name is recorded in.
//! - `index`:        the B-tree a directory is.
//! - `bitmap`:       one bit per cluster, and one per record.
//! - `time`:         the 1601 epoch, in hundred-nanosecond units.
//! - `attrs`:        the attribute word, and the mode a record presents as.
//! - `ident`:        what an inode number is here, which is a record number.
//! - `opts`:         what a mount was asked for, and what it reports back.
//! - `volume`:       a mounted volume, driven against a real medium.
//! - `mount`:        the VFS-facing filesystem, its inodes and operations.

extern crate alloc;

pub mod uapi;
pub mod fixup;
pub mod boot;
pub mod record;
pub mod attrib;
pub mod run;
pub mod lznt;
pub mod upcase;
pub mod upcase_rules;
pub mod name;
pub mod index;
pub mod bitmap;
pub mod time;
pub mod attrs;
pub mod ident;
pub mod opts;
pub mod volume;
pub mod mount;
/// `/proc/fs/ntfs3` entry descriptions, in terms `/proc` does not have to know.
pub mod fsattr;
pub mod procfs;

pub use attrib::Attribute;
pub use boot::{Boot, BootError, Geometry};
pub use mount::{NtfsFs, NTFS_NAME};
pub use opts::Options;
pub use record::{Reference, RecordHeader};
pub use run::{Run, Runs};
pub use uapi::NTFS_SUPER_MAGIC;
pub use volume::{DirEntry, NodeInfo, Volume};

/// The image builder every volume-level test drives.
#[cfg(test)]
#[path = "tests/image.rs"]
pub(crate) mod test_image;
