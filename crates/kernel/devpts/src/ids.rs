//! devpts inode NUMBERS + device identities, drawn from the pseudo-inode
//! registry (`vfs::pseudo_ino::DEVPTS`).
//!
//! A number here is a `st_ino` value, never an identity test — a pty endpoint
//! is recognised by the `PtyEndpointData` devpts installs in `i_private`
//! (`crate::identity`). devpts used to mint from `0x6000_0000`, the base
//! cgroupfs also claimed for its directories, so `pair_for_inode` decoded a
//! cgroup2 directory with a small cgroup id as a PTY master; and the 15-bit
//! index let slave `0x7FFE`/`0x7FFF` alias the two `ptmx` nodes.

use vfs::pseudo_ino::DEVPTS;
use vfs::Ino;

/// `DEVPTS_SUPER_MAGIC` — `statfs` `f_type` for the devpts
/// instance mounted at `/dev/pts`.
pub const DEVPTS_MAGIC: u64 = 0x1cd1;

/// devpts `st_dev`/`fsid`. Linux mounts devpts as its OWN filesystem at
/// `/dev/pts` (distinct from devtmpfs at `/dev`), so its inodes must report a
/// dev number distinct from `devfs::DEVFS_FSID` for `(dev, ino)` uniqueness
/// across the two mounts.
pub const DEVPTS_FSID: u64 = 0x0102_1994_0000_0006;

/// Bits a pts index occupies in an endpoint inode number. Two bits above it
/// select the kind, which is what keeps the `ptmx` nodes out of the endpoint
/// space entirely.
const PTS_INDEX_BITS: u32 = 14;

/// Distinct pts indexes the region names without collision. Above Linux's
/// default `pty.max` of 4096.
pub const MAX_PTY_PAIRS: u32 = 1 << PTS_INDEX_BITS;

const INDEX_MASK: u64 = MAX_PTY_PAIRS as u64 - 1;
const KIND_MASK: u64 = 0b11 << PTS_INDEX_BITS;
const KIND_MASTER: u64 = 0b00 << PTS_INDEX_BITS;
const KIND_SLAVE: u64 = 0b01 << PTS_INDEX_BITS;

/// `/dev/ptmx` sentinel inode. Top of the region, outside both endpoint kinds.
pub(crate) const PTMX_ROOT_INO: Ino = DEVPTS.end();
/// The per-instance `/dev/pts/ptmx` node.
pub(crate) const PTMX_MOUNT_INO: Ino = DEVPTS.end() - 1;

/// `/dev/ptmx` device number (5:2).
pub(crate) const PTMX_RDEV: u32 = 0x0502;
/// Master-half rdev base; the low byte carries the pts index.
pub(crate) const PTY_MASTER_RDEV_BASE: u32 = 0x8000;
/// Slave-half rdev base; the low byte carries the pts index.
pub(crate) const PTY_SLAVE_RDEV_BASE: u32 = 0x8800;

/// `st_ino` of the MASTER half of pty `idx`. # C: O(1)
pub(crate) const fn master_ino(idx: u32) -> Ino {
    DEVPTS.start() | KIND_MASTER | (idx as u64 & INDEX_MASK)
}

/// `st_ino` of the SLAVE half (`/dev/pts/<idx>`) of pty `idx`. # C: O(1)
pub(crate) const fn slave_ino(idx: u32) -> Ino {
    DEVPTS.start() | KIND_SLAVE | (idx as u64 & INDEX_MASK)
}

/// Whether `ino` falls in the endpoint (master or slave) part of the region.
/// A NUMBERING question — ownership is [`crate::identity`]'s. # C: O(1)
pub(crate) const fn is_endpoint_ino(ino: Ino) -> bool {
    if !DEVPTS.contains(ino) { return false; }
    let kind = ino & KIND_MASK;
    kind == KIND_MASTER || kind == KIND_SLAVE
}

// The alias the 15-bit index produced: slave `0x…FFFE`/`0x…FFFF` WERE the two
// ptmx inodes, so `stat` could not tell pty 32766's slave from `/dev/ptmx`.
const _: () = assert!(!is_endpoint_ino(PTMX_ROOT_INO), "ptmx root aliases a pty endpoint");
const _: () = assert!(!is_endpoint_ino(PTMX_MOUNT_INO), "pts/ptmx aliases a pty endpoint");
const _: () = assert!(DEVPTS.contains(master_ino(MAX_PTY_PAIRS - 1)), "master index escapes DEVPTS");
const _: () = assert!(DEVPTS.contains(slave_ino(MAX_PTY_PAIRS - 1)), "slave index escapes DEVPTS");
const _: () = assert!(master_ino(0) != slave_ino(0), "both halves of a pair share one number");
