//! ledger D3 (vfs-model/inode-trait-conflates-iop-fop-aops, inode-side):
//! the object-model rebuild split `address_space_operations` out as
//! `Inode::i_mapping()`, and the inode's `mmap_shared_frame(off)` default
//! FORWARDS to `i_mapping().shared_frame(off)` (Linux: one `address_space`
//! per inode; a `MAP_SHARED` fault aliases the inode's own page-cache frame,
//! so every mapper + `read`/`write` see the same storage). This locks that
//! forwarding in:
//!   * an inode WITH an `i_mapping` returns the mapping's shared frame (not a
//!     fresh private copy) — shared mappings alias file storage;
//!   * an inode WITHOUT an `i_mapping` (the `None` default) returns `None`, so
//!     the fault handler falls back to a private `read`-filled frame.
//! Fixtures over `InodeBuilder`, no global state, no QEMU.

use std::sync::Arc;

use vfs::inode::InodeBuilder;
use vfs::{default_file_ops, default_inode_ops, mk_mode, AddressSpaceOps, FileType, InodeRef};

const PG: u64 = 4096;
/// Base PA the toy address_space hands out; page index folds into the low bits.
const FRAME_BASE: u64 = 0x40_0000;

/// Toy per-inode address_space: one persistent frame per page index, so a
/// repeated `shared_frame(off)` for the same page returns the SAME PA (the
/// aliasing invariant a `MAP_SHARED` mapping relies on).
struct ToyMapping { len: u64 }
impl AddressSpaceOps for ToyMapping {
    fn shared_frame(&self, off: u64) -> vfs::KResult<Option<vfs::SharedFrame>> {
        if off >= self.len { return Ok(None); }      // past EOF: no backing frame
        Ok(Some(vfs::SharedFrame { pa: FRAME_BASE + (off / PG) * PG, map_ref_held: false }))
    }
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> vfs::KResult<usize> { Ok(0) }
    fn size(&self) -> u64 { self.len }
}

/// Frame-backed inode (shmem/tmpfs shape): exposes an `i_mapping`, overrides
/// nothing else of the data path, so `mmap_shared_frame` takes the default
/// forwarding path.
fn mapped(len: u64) -> InodeRef {
    InodeBuilder::new(10, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .size(len).mapping(Arc::new(ToyMapping { len })).build()
}

/// Plain inode with no page-cache (default `i_mapping() == None`).
fn unmapped() -> InodeRef {
    InodeBuilder::new(11, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .size(8192).build()
}

#[test]
fn mmap_shared_frame_forwards_to_i_mapping() {
    let inode = mapped(2 * PG);
    // page 0 and page 1 each alias the mapping's own frame, byte-identical to
    // a direct `i_mapping().shared_frame()` — i.e. the default forwarded.
    assert_eq!(inode.mmap_shared_frame(0).map(|frame| frame.map(|frame| frame.pa)), Ok(Some(FRAME_BASE)));
    assert_eq!(inode.mmap_shared_frame(PG).map(|frame| frame.map(|frame| frame.pa)), Ok(Some(FRAME_BASE + PG)));
    assert_eq!(
        inode.mmap_shared_frame(0),
        inode.i_mapping().unwrap().shared_frame(0),
        "default mmap_shared_frame must equal i_mapping().shared_frame()",
    );
}

#[test]
fn mmap_shared_frame_repeats_alias_same_pa() {
    // The aliasing guarantee: two faults of one page return ONE frame, so two
    // MAP_SHARED mappers share storage rather than diverging.
    let inode = mapped(4 * PG);
    let a = inode.mmap_shared_frame(2 * PG);
    let b = inode.mmap_shared_frame(2 * PG + 17); // mid-page offset, same page
    assert_eq!(a.map(|frame| frame.map(|frame| frame.pa)), Ok(Some(FRAME_BASE + 2 * PG)));
    assert_eq!(a, b, "same page → same aliased frame");
}

#[test]
fn mmap_shared_frame_past_eof_is_none() {
    // Beyond the mapping's size there is no backing frame.
    let inode = mapped(PG);
    assert_eq!(inode.mmap_shared_frame(PG), Ok(None));
    assert_eq!(inode.mmap_shared_frame(10 * PG), Ok(None));
}

#[test]
fn no_mapping_inode_has_no_shared_frame() {
    // Default `i_mapping() == None` ⇒ `mmap_shared_frame` is `None`, so the
    // fault path copies via `read` into a fresh private frame (MAP_PRIVATE).
    let inode = unmapped();
    assert!(inode.i_mapping().is_none());
    assert_eq!(inode.mmap_shared_frame(0), Ok(None));
    assert_eq!(inode.mmap_shared_frame(PG), Ok(None));
}
