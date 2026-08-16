#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! squashfs: what a live image and a container base layer are.
//!
//! Every bootable medium that is not installed, and every layer of every
//! container image built the ordinary way, is a squashfs. Without it those
//! media do not mount at all.
//!
//! Three things make it a different reader from every read-write filesystem
//! here, and each one reaches everything above it:
//!
//! - **Two block encodings, not one.** A metadata block's length word is
//!   sixteen bits with the uncompressed flag at the top; a data block's is
//!   thirty-two with the flag at bit twenty-four. Decoding one with the other's
//!   mask reads the wrong number of bytes from the right offset, which is the
//!   failure that survives a casual look.
//! - **Metadata is a byte STREAM.** Structures straddle compressed block
//!   boundaries, so every read of a structure is a cursor walk and never a
//!   slice.
//! - **The image is immutable and self-describing.** There is no allocator, no
//!   journal and no dirty state; what there is instead is a chain of index
//!   tables whose validity is stated backwards from the end of the image, and
//!   which is checked once at mount so no later lookup can check it differently.
//!
//! Module manifest:
//! - `uapi`:       the on-disk numbers the format is defined in terms of.
//! - `limits`:     the bounds a value read off the medium is checked against.
//! - `compress`:   which decompressor a compressor identifier names.
//! - `block`:      the two block length encodings.
//! - `superblock`: the superblock, and every reason a volume is refused.
//! - `opts`:       what a mount was asked for, and what it reports back.
//! - `volume`:     a mounted volume, driven against a medium.
//! - `mount`:      the VFS-facing filesystem, its inodes and their operations.

extern crate alloc;

pub mod uapi;
pub mod limits;
pub mod compress;
pub mod block;
pub mod superblock;
pub mod opts;
pub mod volume;
pub mod mount;

pub use compress::{Codec, CodecError};
pub use mount::{SquashFs, SQUASHFS_NAME};
pub use opts::{Errors, Options};
pub use superblock::{Super, SuperError};
pub use uapi::{SQUASHFS_MAGIC, SQUASHFS_SUPER_MAGIC};
pub use volume::{DirEntry, Inode, Kind, MountError, Volume};

/// The image builder every volume-level test lays its fixtures out with.
/// # C: see `tests/image.rs`
#[cfg(test)]
#[path = "tests/image.rs"]
pub(crate) mod test_image;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
