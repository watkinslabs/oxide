use core::sync::atomic::AtomicU64;

use vfs::Ino;

/// Inode numbers this filesystem mints, from its own band.
pub(super) const INO_ALLOC_BASE: u64 = vfs::pseudo_ino::HUGETLBFS.start();
pub(super) static NEXT_INO: AtomicU64 = AtomicU64::new(INO_ALLOC_BASE);

/// Root-inode number of every instance; a distinct `s_dev` per mount keeps
/// `(dev, ino)` unique across them.
pub(super) const ROOT_INO: Ino = 2;

/// Root-inode defaults of a mount that names no `mode=`/`uid=`/`gid=`.
pub(super) const DEFAULT_ROOT_MODE: u16 = 0o755;
pub(super) const DEFAULT_ROOT_UID: u32 = 0;
pub(super) const DEFAULT_ROOT_GID: u32 = 0;

/// Permission bits `mode=` may set (`S_ISVTX` plus the nine rwx bits).
pub(super) const MODE_MASK: u32 = 0o1777;

/// Absent maximum or minimum, matching the subpool's own sentinel.
pub(super) const NO_LIMIT: i64 = pmm::hugetlb::NO_LIMIT;
