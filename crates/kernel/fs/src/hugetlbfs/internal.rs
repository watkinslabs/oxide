// The kernel-private hugetlbfs mount.
//
// `memfd_create(MFD_HUGETLB)` and anonymous `mmap(MAP_HUGETLB)` both need a
// hugetlbfs file with no name in any directory. The reference keeps one
// internal mount per granule for exactly this and builds the file on it, so
// the file is a real hugetlbfs file — same inode ops, same page store, same
// accounting — rather than a second kind of object that merely resembles one.

use alloc::sync::{Arc, Weak};

use pmm::hugetlb::{self, HugePageSize};
use sync::{Spinlock, TaskList as TaskListClass};
use vfs::InodeRef;

use super::accounting::HugetlbfsSb;

/// Why a huge-page file could not be created.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HugetlbSetupError {
    /// The size-log named a granule this kernel has no pool for
    /// (`get_hstate_idx` failure — `ENODEV`).
    NoSuchSize,
    /// The pool could not promise the pages the file asked for (`ENOMEM`).
    NoMemory,
    /// The inode itself could not be built (`ENOSPC`).
    NoSpace,
}

/// The private accounting each granule's internal mount uses. Built once and
/// reused, so every anonymous huge-page file of one granule shares one mount
/// exactly as the reference's `hugetlbfs_vfsmount[]` does.
static MOUNT_2M: Spinlock<Option<Arc<HugetlbfsSb>>, TaskListClass> = Spinlock::new(None);
static MOUNT_1G: Spinlock<Option<Arc<HugetlbfsSb>>, TaskListClass> = Spinlock::new(None);

fn slot(size: HugePageSize) -> &'static Spinlock<Option<Arc<HugetlbfsSb>>, TaskListClass> {
    match size { HugePageSize::Huge2M => &MOUNT_2M, HugePageSize::Huge1G => &MOUNT_1G }
}

/// The internal mount's accounting for `size`, creating it on first use.
///
/// It carries no ceiling of its own: an anonymous huge-page mapping is bounded
/// by the global pool, not by a filesystem the caller never mounted.
/// # C: O(1)
fn internal_sb(size: HugePageSize) -> Arc<HugetlbfsSb> {
    let mut g = slot(size).lock();
    if let Some(sb) = g.as_ref() { return sb.clone(); }
    let sb = HugetlbfsSb::unlimited(size);
    *g = Some(sb.clone());
    sb
}

/// Build an anonymous hugetlbfs file of `size` bytes at the granule named by
/// `page_size_log` (0 = the default granule), with `bytes` worth of pages
/// reserved up front.
///
/// Reserving here is what makes `mmap(MAP_HUGETLB)` and
/// `memfd_create(MFD_HUGETLB)` fail at the call rather than at a fault the
/// program cannot handle — the same reason the file-backed path reserves at
/// `mmap`.
/// # C: O(pages)
pub fn hugetlb_file_setup(bytes: u64, page_size_log: u32, perm: u16, uid: u32, gid: u32)
    -> Result<InodeRef, HugetlbSetupError>
{
    let size = hugetlb::size_from_log(page_size_log).ok_or(HugetlbSetupError::NoSuchSize)?;
    let acct = internal_sb(size);
    let inode = super::file::make_file_inode(perm, uid, gid, Weak::new(), acct)
        .ok_or(HugetlbSetupError::NoSpace)?;
    if bytes != 0 {
        super::file::reserve_mapping(&inode, 0, bytes).map_err(|_| HugetlbSetupError::NoMemory)?;
    }
    Ok(inode)
}
