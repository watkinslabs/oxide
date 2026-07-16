use vfs::Ino;

use core::sync::atomic::AtomicU64;

pub(super) const INO_ALLOC_BASE: u64 = 0x4000_0000;
pub(super) static NEXT_INO: AtomicU64 = AtomicU64::new(INO_ALLOC_BASE);

pub(super) const PG: usize = 4096;
pub(super) const FALLBACK_TOTAL_PAGES: u64 = 1 << 30;
/// Root-inode number of every instance (distinct `s_dev` keeps `(dev,ino)`
/// unique across mounts).
pub(super) const ROOT_INO: Ino = 2;
