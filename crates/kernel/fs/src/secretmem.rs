// Secret memory: an anonymous file whose pages are removed from the kernel's
// linear map for as long as the file owns them.
//
// The whole point is the ABSENCE of a kernel mapping. Every ordinary page of
// RAM is reachable from the kernel through the linear map, so a kernel bug that
// follows a stray pointer can read it. A page owned by this file is taken out
// of that map on the fault that allocates it and put back only when the file
// gives it up, so for its whole lifetime the only translation that reaches it
// is the owning process's own.
//
// That contract is why there is deliberately no read or write operation here:
// the content is reachable through a mapping or not at all. It is also why the
// file starts empty — a page can only be faulted below the size the owner set —
// and why the size may only be set while the file is still empty, since growing
// it later would silently expose pages that were never taken out of the map.
//
// Availability is not assumed. Whether single pages can leave the linear map at
// all is an architectural property; where they cannot, this file must not be
// created, because handing back ordinary RAM under this name is exactly the lie
// the interface exists to avoid.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::dentry::{Dentry, DentryOps};
use vfs::{AddressSpaceOps, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, mk_mode};

/// Page granule of the backing store.
const PG: u64 = hal::PAGE_SIZE_BYTES;
/// Rendered name of a secret-memory file.
pub const SECRETMEM_NAME: &str = "secretmem";
/// Permission bits of a freshly created secret-memory file.
const SECRETMEM_PERM: u16 = 0o777;

/// Live secret-memory files. Read by the memory hot-unplug and hibernation
/// paths, which must refuse to move or write out memory that has deliberately
/// been made unreachable, and by the syscall, which refuses to create the file
/// that would overflow this count rather than wrap it.
static USERS: AtomicI64 = AtomicI64::new(0);

/// Whether any secret memory exists right now.
/// # C: O(1)
pub fn secretmem_active() -> bool { USERS.load(Ordering::Acquire) != 0 }

/// Whether one more file may be created. A count that has gone negative is a
/// count that wrapped, and the honest answer is to refuse the file.
/// # C: O(1)
pub fn secretmem_can_create() -> bool { USERS.load(Ordering::Acquire) >= 0 }

/// Per-inode store: page index to the frame that page owns. Sparse — an index
/// with no entry has never been faulted, and reads zero once it is.
pub struct SecretmemData {
    pages: Spinlock<BTreeMap<u64, u64>, TaskListClass>,
    len: AtomicU64,
}

/// Translate a linear-map failure into the file-system error the fault reports.
/// # C: O(1)
fn map_err(e: syscall::errno::Errno) -> VfsError {
    if e == syscall::errno::Errno::Enomem { VfsError::Enomem } else { VfsError::Einval }
}

/// Take one page out of the kernel's linear map and make it visible everywhere.
/// The page must already hold its final contents: after this returns, the
/// kernel cannot reach it to fill it in.
/// # C: O(walk depth) + one interprocessor round trip
fn hide_page(pa: u64) -> KResult<()> {
    pmm::setup::set_direct_map_invalid_noflush(pa).map_err(map_err)?;
    pmm::setup::flush_kernel_page(pa);
    Ok(())
}

/// Put one page back into the linear map and erase it. Restoration comes first
/// because the erase is performed THROUGH that mapping, and the erase happens
/// at all because the next owner of this frame must not inherit the secret.
/// # C: O(walk depth) + one interprocessor round trip
fn reveal_and_erase(pa: u64) {
    if pmm::setup::set_direct_map_default_noflush(pa).is_err() { return; }
    pmm::setup::flush_kernel_page(pa);
    let Some(ptr) = pmm::setup::frame_ptr(pa) else { return; };
    // SAFETY: `ptr` names the whole frame, which is back in the linear map and
    // is about to be released, so no other owner can be reading it.
    hal::zerotrap::trap(ptr as *const u8, PG as usize);
    // SAFETY: same frame, page-granule length, exclusively ours at this point.
    unsafe { core::ptr::write_bytes(ptr, 0, PG as usize); }
}

/// Release one page: back into the map, erased, then handed to the allocator.
/// # C: O(walk depth)
fn release_page(pa: u64) {
    reveal_and_erase(pa);
    // SAFETY: this is the inode's own reference on `pa`, dropped exactly once;
    // no mapping outlives the inode, which every mapper pins.
    unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
}

impl SecretmemData {
    /// Logical size.
    /// # C: O(1)
    pub fn len(&self) -> u64 { self.len.load(Ordering::Acquire) }

    /// Set the logical size. Only legal while the file is still empty, because
    /// a later growth would publish page indices that never went through the
    /// fault that removes their pages from the linear map, and a shrink would
    /// have to reveal pages a mapper may still hold.
    /// # C: O(1)
    fn set_len(&self, len: u64) -> KResult<()> {
        if self.len.load(Ordering::Acquire) != 0 { return Err(VfsError::Einval); }
        self.len.store(len, Ordering::Release);
        Ok(())
    }
}

impl Drop for SecretmemData {
    /// # C: O(N_pages)
    fn drop(&mut self) {
        let g = self.pages.lock();
        for (_, &pa) in g.iter() { release_page(pa); }
    }
}

impl AddressSpaceOps for SecretmemData {
    /// The fault that owns the whole contract: allocate a zeroed frame, take it
    /// out of the linear map, and only then publish it at this index. Publishing
    /// first would leave a window in which the page is reachable from the kernel
    /// and already findable by a second mapper.
    /// # C: O(log N_pages) + one interprocessor round trip on first touch
    fn shared_frame(&self, off: u64) -> KResult<Option<vfs::SharedFrame>> {
        if off >= self.len.load(Ordering::Acquire) { return Err(VfsError::Einval); }
        let idx = off / PG;
        let mut g = self.pages.lock();
        if let Some(&pa) = g.get(&idx) {
            // SAFETY: the index lock keeps this page published until the
            // prospective page-table reference has been acquired.
            unsafe { pmm::setup::inc_ref(pa); }
            return Ok(Some(vfs::SharedFrame { pa, map_ref_held: true }));
        }
        let pa = pmm::setup::alloc_object_frame().ok_or(VfsError::Enomem)?;
        let Some(ptr) = pmm::setup::frame_ptr(pa) else {
            // SAFETY: an unpublished allocation holding only its own reference.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            return Err(VfsError::Enomem);
        };
        // SAFETY: `ptr` names the whole freshly allocated frame; nothing else
        // can reach it yet, and it must be clean BEFORE it leaves the map,
        // because afterwards the kernel cannot write to it at all.
        hal::zerotrap::trap(ptr as *const u8, PG as usize);
        // SAFETY: same frame, page-granule length, exclusively ours.
        unsafe { core::ptr::write_bytes(ptr, 0, PG as usize); }
        if let Err(e) = hide_page(pa) {
            // SAFETY: the failed attempt published nothing; this is still the
            // sole reference. `hide_page` restores nothing because it changed
            // nothing it did not undo.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            return Err(e);
        }
        g.insert(idx, pa);
        // SAFETY: published under the index lock; this reference is the one the
        // caller installs in a page table.
        unsafe { pmm::setup::inc_ref(pa); }
        Ok(Some(vfs::SharedFrame { pa, map_ref_held: true }))
    }

    /// Faulting around means installing translations for pages the process did
    /// not ask for. Every such page would have to leave the linear map first,
    /// so the cheap speculative path this exists for does not apply; only pages
    /// already owned are offered, and only when they exist.
    /// # C: O(log N_pages)
    fn fault_around_frame(&self, off: u64) -> KResult<Option<vfs::SharedFrame>> {
        let g = self.pages.lock();
        let Some(&pa) = g.get(&(off / PG)) else { return Ok(None); };
        // SAFETY: the index lock holds the page published across the handoff.
        unsafe { pmm::setup::inc_ref(pa); }
        Ok(Some(vfs::SharedFrame { pa, map_ref_held: true }))
    }

    /// There is no path by which the kernel copies these bytes out. This is
    /// what makes a private mapping, a read, and a readahead of this file all
    /// impossible rather than merely discouraged: they all end here.
    /// # C: O(1)
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> KResult<usize> { Err(VfsError::Einval) }

    /// Reading ahead means faulting pages nobody asked for. Refused for the
    /// same reason fault-around is.
    /// # C: O(1)
    fn readahead(&self, _start: u64, _nr_pages: u64) {}

    /// These pages are not a cache of anything, so there is nothing to write
    /// back — and nothing anywhere else that could be read instead.
    /// # C: O(1)
    fn writeback(&self) -> Result<(), ()> { Ok(()) }

    /// A page here cannot be moved: relocating it means copying it through the
    /// kernel, which is precisely the access this file exists to prevent. It is
    /// also never a candidate for eviction, because it is never offered to the
    /// reclaim lists at all.
    /// # C: O(1)
    fn madvise_pageout(&self, _off: u64, _len: u64) -> Option<KResult<usize>> {
        Some(Err(VfsError::Ebusy))
    }

    /// Report resident pages so the owner can ask which of its own pages exist.
    /// # C: O(log N_pages)
    fn mincore_page(&self, off: u64) -> bool { self.pages.lock().contains_key(&(off / PG)) }

    /// Not shmem: an "already in the backing store but absent from the page
    /// table" state is not observable here, and the machinery that keys on it
    /// would need the kernel access this file denies.
    /// # C: O(1)
    fn is_shmem(&self) -> bool { false }

    /// # C: O(1)
    fn size(&self) -> u64 { self.len.load(Ordering::Acquire) }
}

/// `i_op`: size is settable exactly once, while the file is still empty.
struct SecretmemInodeOps;
impl InodeOps for SecretmemInodeOps {
    /// # C: O(1)
    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        let d = inode.private::<SecretmemData>().ok_or(VfsError::Einval)?;
        d.set_len(len)?;
        inode.set_size(len);
        Ok(())
    }
}

/// `i_fop`: no read, no write — the defaults refuse both, which is the whole
/// operation table. Closing the last reference retires the file's claim on the
/// global count.
struct SecretmemFileOps;
impl FileOps for SecretmemFileOps {
    /// # C: O(1)
    fn on_release(&self, _inode: &Inode) { USERS.fetch_sub(1, Ordering::AcqRel); }
}

/// `d_op` for a secret-memory file. It lives on its own pseudo filesystem, so
/// its rendered name is its own, not the shared anonymous-inode spelling.
/// # C: O(1)
fn secretmem_dname(_d: &Dentry) -> String { String::from(SECRETMEM_NAME) }

/// Dentry operations for the secret-memory pseudo file.
pub static SECRETMEM_OPS: DentryOps = DentryOps {
    d_dname: Some(secretmem_dname),
    d_hash: None, d_compare: None, d_revalidate: None, d_weak_revalidate: None,
    d_delete: None, d_release: None, d_iput: None, d_init: None, d_prune: None,
};

/// Build one secret-memory inode, owned by `uid`/`gid`. The file is a regular
/// file of size zero: everything about it that differs is in its operations,
/// not in what it claims to be, so a process that stats it learns nothing.
/// # C: O(1)
pub fn secretmem_inode(uid: u32, gid: u32) -> InodeRef {
    USERS.fetch_add(1, Ordering::AcqRel);
    let data = Arc::new(SecretmemData {
        pages: Spinlock::new(BTreeMap::new()),
        len: AtomicU64::new(0),
    });
    let mapping: Arc<dyn AddressSpaceOps> = data.clone();
    InodeBuilder::new(next_secretmem_ino(), mk_mode(FileType::Regular, SECRETMEM_PERM),
                      Arc::new(SecretmemInodeOps), Arc::new(SecretmemFileOps))
        .owner(uid, gid)
        .mapping(mapping)
        .private(data)
        .build()
}

/// Is this inode a secret-memory file? The mapping path asks, because a
/// secret-memory mapping carries properties the caller can neither request
/// nor decline. Identity is the private payload, which only this module
/// installs.
/// # C: O(1)
pub fn is_secretmem(inode: &InodeRef) -> bool { inode.private::<SecretmemData>().is_some() }

/// Inode numbers for the secret-memory pseudo filesystem.
/// # C: O(1)
fn next_secretmem_ino() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file whose size was never set owns no page indices at all, so the
    /// fault that would allocate a page cannot even be reached. This is the
    /// reason the size is settable while empty and never afterwards.
    #[test]
    fn a_zero_sized_file_refuses_every_offset() {
        let d = SecretmemData { pages: Spinlock::new(BTreeMap::new()), len: AtomicU64::new(0) };
        assert_eq!(d.shared_frame(0).err(), Some(VfsError::Einval));
        assert_eq!(d.shared_frame(PG).err(), Some(VfsError::Einval));
        assert_eq!(d.size(), 0);
    }

    /// Size may be set once, while empty, and never again — a later change
    /// would publish indices whose pages never left the linear map.
    #[test]
    fn size_is_settable_only_while_the_file_is_empty() {
        let d = SecretmemData { pages: Spinlock::new(BTreeMap::new()), len: AtomicU64::new(0) };
        assert_eq!(d.set_len(2 * PG), Ok(()));
        assert_eq!(d.len(), 2 * PG);
        assert_eq!(d.set_len(3 * PG), Err(VfsError::Einval));
        assert_eq!(d.set_len(0), Err(VfsError::Einval));
        assert_eq!(d.len(), 2 * PG, "a refused resize must not take effect");
    }

    /// An offset past the size is refused even once the size is set, so a
    /// mapping longer than the file cannot fault a page into existence.
    #[test]
    fn offsets_past_the_size_stay_refused() {
        let d = SecretmemData { pages: Spinlock::new(BTreeMap::new()), len: AtomicU64::new(0) };
        assert_eq!(d.set_len(PG), Ok(()));
        assert_eq!(d.shared_frame(PG).err(), Some(VfsError::Einval));
        assert_eq!(d.shared_frame(PG * 4).err(), Some(VfsError::Einval));
    }

    /// There is no read path. A private mapping, a `read`, and readahead all
    /// arrive here, and all get the same answer.
    #[test]
    fn nothing_can_copy_the_contents_out_through_the_kernel() {
        let d = SecretmemData { pages: Spinlock::new(BTreeMap::new()), len: AtomicU64::new(PG) };
        let mut buf = [0u8; 8];
        assert_eq!(d.read_at(0, &mut buf), Err(VfsError::Einval));
    }

    /// Moving a page means copying it through the kernel, which is the access
    /// this file denies; the request is refused rather than silently skipped.
    #[test]
    fn pages_refuse_to_be_moved() {
        let d = SecretmemData { pages: Spinlock::new(BTreeMap::new()), len: AtomicU64::new(PG) };
        assert_eq!(d.madvise_pageout(0, PG), Some(Err(VfsError::Ebusy)));
    }

    /// An address space whose pages are unreachable from the kernel must not be
    /// mistaken for one whose pages are merely resident-but-unmapped; the
    /// machinery keyed on that state needs the access this file denies.
    #[test]
    fn is_not_reported_as_a_resident_backing_store() {
        let d = SecretmemData { pages: Spinlock::new(BTreeMap::new()), len: AtomicU64::new(PG) };
        assert!(!d.is_shmem());
    }

    /// The creation count must refuse to wrap rather than hand out a file the
    /// accounting can no longer describe.
    #[test]
    fn creation_is_refused_once_the_count_has_wrapped() {
        let saved = USERS.load(Ordering::Acquire);
        USERS.store(0, Ordering::Release);
        assert!(secretmem_can_create());
        assert!(!secretmem_active());
        USERS.store(1, Ordering::Release);
        assert!(secretmem_active());
        USERS.store(-1, Ordering::Release);
        assert!(!secretmem_can_create());
        USERS.store(saved, Ordering::Release);
    }
}
