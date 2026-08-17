#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! F2FS: what flash is formatted with when the flash is the point.
//!
//! Android's userdata partition, most eMMC and UFS root filesystems, and a
//! growing share of SSD-backed systems are this. It is log-structured: nothing
//! is overwritten in place, so every structure exists at two addresses and a
//! CHECKPOINT says which of the two is current. That one idea reaches every
//! layer of the reader, and each place it is ignored produces the same failure
//! — a clean read of stale data, with no error anywhere:
//!
//! - **Both node-table copies are valid.** A version bitmap in the checkpoint
//!   picks one. Reading the first always returns the previous checkpoint's
//!   addresses for half the volume.
//! - **The journal beats the table.** Entries changed recently were parked in
//!   the current segment's summary block instead of being written back, so a
//!   reader that consults only the table sees the pre-change address.
//! - **The address array does not start where the layout puts it.** Extra
//!   attributes overlay its head and an inline attribute reservation takes its
//!   tail, both per inode. Getting either wrong reads attribute bytes as block
//!   addresses.
//!
//! Writing follows the same idea and is the same trap. Nothing is updated in
//! place: a changed byte takes a fresh block from one of six open logs,
//! releases the old one, and rewrites every node above it — so one write moves
//! the direct node and the inode too. None of it is visible until a CHECKPOINT
//! is written, to the OTHER of the two packs, with the version raised by one.
//! Writing a checkpoint over the pack it replaces is the one thing that would
//! make a crash unrecoverable.
//!
//! Module manifest:
//! - `uapi`:       the on-disk numbers, offsets and derived sizes.
//! - `flags`:      the feature, checkpoint, inline, attribute and type bits.
//! - `limits`:     what the format admits and what this build refuses past.
//! - `checksum`:   the one CRC, its unusual convention, and what it seals.
//! - `features`:   what a volume's feature word permits this mount to do.
//! - `sb`:         the superblock, and whether its fields agree.
//! - `sbwrite`:    changing the superblock, and putting both copies back.
//! - `sbflags`:    the volume-wide conditions a mount is in, as one word.
//! - `checkpoint`: which pack is current, and where its bitmaps are.
//! - `summary`:    the summary block, and the two journals inside it.
//! - `nat`:        a node id into the address of its node block.
//! - `sit`:        a segment number into what is live inside it.
//! - `node`:       node blocks: the footer, the inode, the index path.
//! - `hash`:       the name hash that picks a directory bucket.
//! - `dirent`:     entries, their four parallel arrays, and bucket addressing.
//! - `xattr`:      the attribute region, assembled from its two halves.
//! - `mode`:       the stored mode word, and the device number beside it.
//! - `compress`:   compressed clusters, and the codecs that unpack them.
//! - `casefold`:   case-insensitive name resolution.
//! - `crypto`:     file-name and file-contents encryption.
//! - `quota`:      per-identity usage accounting.
//! - `verity`:     the descriptor a verity-protected file carries.
//! - `opts`:       what a mount was asked for, and what it reports back.
//! - `extent`:     the read and block-age extent caches, and their LRU.
//! - `filemap`:    a file's data pages, keyed by inode and file offset.
//! - `freenid`:    node ids nothing is using, and how one is handed out.
//! - `atgc`:       age-threshold victim selection, and its candidate tree.
//! - `fault`:      failures injected on purpose, at named sites and a rate.
//! - `stats`:      what a mount has done, and what it looks like right now.
//! - `atomic`:     writes that become visible together or not at all.
//! - `pin`:        files whose blocks are promised never to move.
//! - `swap`:       a file the paging code addresses by block.
//! - `defrag`:     rewriting a range so its blocks land next to each other.
//! - `moverange`:  handing a range of blocks from one file to another.
//! - `sectrim`:    destroying a file's block contents where they lie.
//! - `devices`:    the member devices a volume spans, and their address map.
//! - `zoned`:      what a drive's zones permit, where they dictate placement.
//! - `volume`:     a mounted volume, read and written against a real medium.
//! - `bg`:         the cleaner and discard threads, and the balance path.
//! - `mount`:      the VFS-facing filesystem, its inodes and their operations.
//! - `ioctl`:      the commands a caller sends, who may send them, and what they do.

extern crate alloc;

pub mod uapi;
pub mod flags;
pub mod limits;
pub mod checksum;
pub mod features;
pub mod sb;
pub mod devices;
pub mod zoned;
pub mod sbwrite;
pub mod sbflags;
pub mod checkpoint;
pub mod summary;
pub mod nat;
pub mod sit;
pub mod node;
pub mod hash;
pub mod dirent;
pub mod xattr;
pub mod mode;
pub mod compress;
pub mod casefold;
pub mod crypto;
pub mod quota;
pub mod verity;
pub mod opts;
pub mod consistency;
pub mod fallocate;
pub mod errrec;
pub mod extent;
pub mod filemap;
pub mod freenid;
pub mod atgc;
pub mod fault;
pub mod atomic;
pub mod pin;
pub mod swap;
pub mod defrag;
pub mod moverange;
pub mod sectrim;
pub mod volume;
pub mod bg;
pub mod mount;
pub mod ioctl;
pub mod fsattr;
pub mod procfs;
pub mod stats;
pub mod sysfs;

pub use checkpoint::Checkpoint;
pub use features::{Access, Refusal};
pub use mount::{errno_to_vfs, F2fs, F2FS_NAME};
pub use node::Inode;
pub use opts::Options;
pub use sb::SuperBlock;
pub use uapi::F2FS_SUPER_MAGIC;
pub use volume::{DirEntry, Volume};

/// The image builder every volume-level test drives. # C: see `tests/image.rs`
#[cfg(test)]
#[path = "tests/image.rs"]
pub(crate) mod test_image;
