use alloc::sync::Weak;

use vfs::{Ino, InodeRef};
use vfs::superblock::SuperBlock;

use core::sync::atomic::Ordering;

use super::limits::NEXT_INO;
use super::uapi::TMPFS_FSID;

/// `fsid` from an inode's owning SB, else the tmpfs fallback. # C: O(1)
pub(super) fn fsid_of(sb: &Weak<SuperBlock>) -> u64 {
    sb.upgrade().map(|s| s.s_dev).unwrap_or(TMPFS_FSID)
}

/// Allocate a fresh tmpfs inode number. # C: O(1)
pub(super) fn next_ino() -> Ino { NEXT_INO.fetch_add(1, Ordering::Relaxed) }

/// [inode D2] Route a freshly-built inode through the owning SB's inode cache
/// (Linux `iget`), so a later `ilookup`/`iget` of the same `ino` returns the
/// SAME `Arc` (shared inode identity) and the inode is visible in `s_inodes`
/// from build time — mirroring ext4's `wrap_*_ino` (rootfs/ops.rs). Before the
/// SB is back-stamped (the root inode built at `fill_super`) or for an
/// anonymous inode (memfd/coredump) with no owning SB, there is no cache to
/// register in → build directly. tmpfs always allocates a FRESH `ino`, so the
/// icache is always a build-miss and `iget` is refcount-NEUTRAL: the build sets
/// `i_count == 1`, exactly the single strong reference the tree's `kids` map (or
/// the open file) then holds. Reclaim stays Arc/`Weak`-driven (the cache slot is
/// a `Weak`; the last strong `Arc` dropped → `Inode::Drop` frees the frames →
/// the `Weak` dies), identical to ext4 which likewise never `iput`s.
/// Lock order: a caller holding the parent dir's `kids`/`sb` (Inode rank 40)
/// then takes the icache (Superblock rank 60) — ascending, per `06§3.6`. # C: O(log N_ino)
pub(super) fn iget_or_build(sb: &Weak<SuperBlock>, ino: Ino, build: impl FnOnce() -> InodeRef) -> InodeRef {
    match sb.upgrade() {
        Some(s) => s.iget(ino, build),
        None    => build(),
    }
}
