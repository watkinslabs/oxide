//! inode-D4b (statx richness): `generic_fillattr` (Linux `fs/stat.c`) populates
//! the statx result mask (`stx_mask`), the creation time (`stx_btime` +
//! `STATX_BTIME`), and the `stx_attributes`/`stx_attributes_mask` flag report
//! derived from the VFS `i_flags`. Driven over minimal `Inode` impls, no QEMU.
//!
//! Linux contract pinned here:
//!   * `stx_mask` reflects EXACTLY the filled fields — always the eleven
//!     `STATX_BASIC_STATS`, plus `STATX_BTIME` only when the inode stores a
//!     real birth time (never substituted from ctime).
//!   * `stx_attributes` carries `STATX_ATTR_IMMUTABLE`/`STATX_ATTR_APPEND`
//!     translated from `S_IMMUTABLE`/`S_APPEND`, masked by an
//!     `stx_attributes_mask` advertising exactly those two understood bits.

use vfs::getattr::{
    STATX_ATTR_APPEND, STATX_ATTR_IMMUTABLE, STATX_BASIC_STATS, STATX_BTIME,
};
use vfs::inode::{Inode, S_APPEND, S_IMMUTABLE};
use vfs::{FileType, InodeRef, KResult, VfsError, IDENTITY};

/// Regular file with optional birth time and settable `i_flags`.
struct TFile { flags: u32, btime: Option<u64> }
impl Inode for TFile {
    fn ino(&self) -> vfs::Ino { 7 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn perm(&self) -> Option<u16> { Some(0o644) }
    fn i_flags(&self) -> u32 { self.flags }
    fn btime(&self) -> Option<u64> { self.btime }
}

/// No birth time → `stx_mask` is exactly `STATX_BASIC_STATS` (BTIME clear), and
/// `stx_btime` reads back 0.
#[test]
fn mask_is_basic_stats_without_btime() {
    let st = vfs::generic_fillattr(&TFile { flags: 0, btime: None }, &IDENTITY, None);
    assert_eq!(st.result_mask, STATX_BASIC_STATS, "exactly the base fields, no more");
    assert_eq!(st.result_mask & STATX_BTIME, 0, "STATX_BTIME clear when no birth time");
    assert_eq!(st.btime_ns, 0, "btime field zero when unavailable");
}

/// A stored birth time adds `STATX_BTIME` to the mask and carries the value.
#[test]
fn btime_sets_mask_bit_and_value() {
    let st = vfs::generic_fillattr(&TFile { flags: 0, btime: Some(1_234_000_000_999) }, &IDENTITY, None);
    assert_eq!(st.result_mask & STATX_BTIME, STATX_BTIME, "STATX_BTIME set when present");
    assert_eq!(st.result_mask, STATX_BASIC_STATS | STATX_BTIME, "base set unchanged, only BTIME added");
    assert_eq!(st.btime_ns, 1_234_000_000_999, "btime value passed through");
}

/// `i_flags` immutable/append map onto `stx_attributes`; the mask advertises
/// exactly the two understood bits regardless of which are set.
#[test]
fn attributes_track_iflags() {
    // Neither flag.
    let none = vfs::generic_fillattr(&TFile { flags: 0, btime: None }, &IDENTITY, None);
    assert_eq!(none.attributes, 0, "no attrs when no flags");
    assert_eq!(none.attributes_mask, STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND,
               "mask always advertises the two understood bits");

    // Immutable only.
    let imm = vfs::generic_fillattr(&TFile { flags: S_IMMUTABLE, btime: None }, &IDENTITY, None);
    assert_eq!(imm.attributes, STATX_ATTR_IMMUTABLE, "S_IMMUTABLE → STATX_ATTR_IMMUTABLE");

    // Append only.
    let app = vfs::generic_fillattr(&TFile { flags: S_APPEND, btime: None }, &IDENTITY, None);
    assert_eq!(app.attributes, STATX_ATTR_APPEND, "S_APPEND → STATX_ATTR_APPEND");

    // Both, plus an unrelated S_* bit that must NOT leak into stx_attributes.
    let both = vfs::generic_fillattr(
        &TFile { flags: S_IMMUTABLE | S_APPEND | (1 << 1), btime: None }, &IDENTITY, None);
    assert_eq!(both.attributes, STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND,
               "only immutable+append surface; other i_flags bits ignored");
    assert_eq!(both.attributes & !both.attributes_mask, 0,
               "every reported attribute bit is within attributes_mask");
}

/// The default `Inode::btime()` is `None` (no birth time) for an inode that
/// does not override it — so plain pseudo-fs inodes leave STATX_BTIME clear.
#[test]
fn default_btime_none() {
    struct Plain;
    impl Inode for Plain {
        fn ino(&self) -> vfs::Ino { 8 }
        fn file_type(&self) -> FileType { FileType::Regular }
        fn size(&self) -> u64 { 0 }
        fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    }
    assert_eq!(Plain.btime(), None);
    let st = vfs::generic_fillattr(&Plain, &IDENTITY, None);
    assert_eq!(st.result_mask & STATX_BTIME, 0);
}
