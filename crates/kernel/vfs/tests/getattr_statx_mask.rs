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
use vfs::{FileType, InodeBuilder, InodeRef, S_APPEND, S_IMMUTABLE, IDENTITY,
          default_file_ops, default_inode_ops, mk_mode};

/// Regular file with optional birth time and settable `i_flags`.
fn tfile(flags: u32, btime: Option<u64>) -> InodeRef {
    let mut b = InodeBuilder::new(7, mk_mode(FileType::Regular, 0o644),
            default_inode_ops(), default_file_ops()).i_flags(flags);
    if let Some(t) = btime { b = b.btime(t); }
    b.build()
}

/// No birth time → `stx_mask` is exactly `STATX_BASIC_STATS` (BTIME clear), and
/// `stx_btime` reads back 0.
#[test]
fn mask_is_basic_stats_without_btime() {
    let st = vfs::generic_fillattr(&tfile(0, None), &IDENTITY, None);
    assert_eq!(st.result_mask, STATX_BASIC_STATS, "exactly the base fields, no more");
    assert_eq!(st.result_mask & STATX_BTIME, 0, "STATX_BTIME clear when no birth time");
    assert_eq!(st.btime_ns, 0, "btime field zero when unavailable");
}

/// A stored birth time adds `STATX_BTIME` to the mask and carries the value.
#[test]
fn btime_sets_mask_bit_and_value() {
    let st = vfs::generic_fillattr(&tfile(0, Some(1_234_000_000_999)), &IDENTITY, None);
    assert_eq!(st.result_mask & STATX_BTIME, STATX_BTIME, "STATX_BTIME set when present");
    assert_eq!(st.result_mask, STATX_BASIC_STATS | STATX_BTIME, "base set unchanged, only BTIME added");
    assert_eq!(st.btime_ns, 1_234_000_000_999, "btime value passed through");
}

/// `i_flags` immutable/append map onto `stx_attributes`; the mask advertises
/// exactly the two understood bits regardless of which are set.
#[test]
fn attributes_track_iflags() {
    // Neither flag.
    let none = vfs::generic_fillattr(&tfile(0, None), &IDENTITY, None);
    assert_eq!(none.attributes, 0, "no attrs when no flags");
    assert_eq!(none.attributes_mask, STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND,
               "mask always advertises the two understood bits");

    // Immutable only.
    let imm = vfs::generic_fillattr(&tfile(S_IMMUTABLE, None), &IDENTITY, None);
    assert_eq!(imm.attributes, STATX_ATTR_IMMUTABLE, "S_IMMUTABLE → STATX_ATTR_IMMUTABLE");

    // Append only.
    let app = vfs::generic_fillattr(&tfile(S_APPEND, None), &IDENTITY, None);
    assert_eq!(app.attributes, STATX_ATTR_APPEND, "S_APPEND → STATX_ATTR_APPEND");

    // Both, plus an unrelated S_* bit that must NOT leak into stx_attributes.
    let both = vfs::generic_fillattr(
        &tfile(S_IMMUTABLE | S_APPEND | (1 << 1), None), &IDENTITY, None);
    assert_eq!(both.attributes, STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND,
               "only immutable+append surface; other i_flags bits ignored");
    assert_eq!(both.attributes & !both.attributes_mask, 0,
               "every reported attribute bit is within attributes_mask");
}

/// The default `Inode::btime()` is `None` (no birth time) for an inode that
/// does not override it — so plain pseudo-fs inodes leave STATX_BTIME clear.
#[test]
fn default_btime_none() {
    // A plain inode built with no birth time leaves `btime()` at `None`.
    let plain = InodeBuilder::new(8, mk_mode(FileType::Regular, 0o644),
            default_inode_ops(), default_file_ops()).build();
    assert_eq!(plain.btime(), None);
    let st = vfs::generic_fillattr(&plain, &IDENTITY, None);
    assert_eq!(st.result_mask & STATX_BTIME, 0);
}
