// Link objects: fd-backed cgroup and LSM links, plus the link id registry
// and the two-phase publication that keeps an id unobservable until the
// attachment behind it exists.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use syscall::errno::Errno;
use vfs::{FileType, InodeRef, InodeBuilder, default_inode_ops, default_file_ops, mk_mode};

use super::{BPF_FD_MODE, ids};

static NEXT_CGROUP_LINK_ID: AtomicU32 = AtomicU32::new(1);

enum CgroupLinkIdSlot {
    Unsettled,
    Settled(alloc::sync::Weak<vfs::Inode>),
}

static CGROUP_LINKS_BY_ID: Spinlock<BTreeMap<u32, CgroupLinkIdSlot>, TaskListClass> =
    Spinlock::new(BTreeMap::new());

/// fd-backed BPF LSM link. Dropping the last fd reference removes the
/// registry entry.
pub struct BpfLsmLinkInode {
    pub(super) id: u64,
    pub(super) _hook: crate::bpf_lsm::Hook,
    pub(super) _prog: InodeRef,
}

impl Drop for BpfLsmLinkInode {
    fn drop(&mut self) { crate::bpf_lsm::unregister(self.id); }
}

/// Build the `Arc<Inode>` for a BPF LSM link fd. # C: O(1)
pub fn make_bpf_lsm_link_inode(link: BpfLsmLinkInode) -> InodeRef {
    InodeBuilder::new(ids::INO_LINK, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .private(Arc::new(link))
        .build()
}

/// fd-backed cgroup link. The cgroup hierarchy owns attachment state; the
/// link pins its program and removes that exact entry on final close.
pub struct BpfCgroupLinkInode {
    pub(super) id: u32,
    pub(super) cgid: u64,
    pub(super) attach_type: cgroup::CgroupBpfAttachType,
    pub(super) _prog: InodeRef,
    attached: AtomicBool,
}

impl Drop for BpfCgroupLinkInode {
    fn drop(&mut self) {
        if self.attached.load(Ordering::Acquire) {
            let _ = cgroup::bpf::detach_link(self.cgid, self.attach_type, self.id as u64);
            CGROUP_LINKS_BY_ID.lock().remove(&self.id);
        }
    }
}

/// Build an unsettled cgroup BPF link fd inode. # C: O(1)
pub fn make_bpf_cgroup_link_inode(link: BpfCgroupLinkInode) -> InodeRef {
    InodeBuilder::new(ids::INO_LINK, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .private(Arc::new(link))
        .build()
}

fn reserve_cgroup_link_id() -> u32 {
    loop {
        let id = NEXT_CGROUP_LINK_ID.fetch_add(1, Ordering::Relaxed);
        if id == 0 { continue; }
        let mut links = CGROUP_LINKS_BY_ID.lock();
        if links.contains_key(&id) { continue; }
        links.insert(id, CgroupLinkIdSlot::Unsettled);
        return id;
    }
}

/// Resolve a settled link by id. A reserved-but-unpublished id answers
/// `EAGAIN`, matching the window in which the object exists but its
/// attachment has not been made observable. # C: O(log links)
pub(crate) fn cgroup_link_by_id(id: u32) -> Result<InodeRef, Errno> {
    if id == 0 { return Err(Errno::Enoent); }
    let links = CGROUP_LINKS_BY_ID.lock();
    match links.get(&id) {
        Some(CgroupLinkIdSlot::Unsettled) => Err(Errno::Eagain),
        Some(CgroupLinkIdSlot::Settled(link)) => match link.upgrade() {
            Some(inode) => Ok(inode),
            None => Err(Errno::Enoent),
        },
        None => Err(Errno::Enoent),
    }
}

/// Lowest live link id strictly above `start`. # C: O(live links)
pub(crate) fn next_live_link_id(start: u32) -> Option<u32> {
    let mut links = CGROUP_LINKS_BY_ID.lock();
    let id = links.range((core::ops::Bound::Excluded(start), core::ops::Bound::Unbounded))
        .find_map(|(id, slot)| match slot {
            CgroupLinkIdSlot::Settled(link) if link.strong_count() != 0 => Some(*id),
            _ => None,
        });
    links.retain(|_, slot| match slot {
        CgroupLinkIdSlot::Unsettled => true,
        CgroupLinkIdSlot::Settled(link) => link.strong_count() != 0,
    });
    id
}

fn settle_cgroup_link_id(id: u32, inode: &InodeRef) {
    let old = CGROUP_LINKS_BY_ID.lock()
        .insert(id, CgroupLinkIdSlot::Settled(Arc::downgrade(inode)));
    hal::kassert!(
        matches!(old, Some(CgroupLinkIdSlot::Unsettled)),
        "settling an unreserved BPF cgroup link ID"
    );
}

fn cancel_cgroup_link_id(id: u32) {
    let mut links = CGROUP_LINKS_BY_ID.lock();
    if matches!(links.get(&id), Some(CgroupLinkIdSlot::Unsettled)) { links.remove(&id); }
}

/// Primed cgroup link resources. Attachment happens while the ID remains
/// unobservable and fd publication cannot fail. # C: O(fd words + log links)
pub(crate) struct BpfCgroupLinkPrimer {
    id: u32,
    fd: i32,
    fdt: Arc<vfs::FdTable>,
    file: Arc<vfs::File>,
    inode: InodeRef,
    settled: bool,
}

impl BpfCgroupLinkPrimer {
    pub(crate) fn id(&self) -> u32 { self.id }

    /// Publish the attached object by ID, then install the reserved fd.
    /// # C: O(log links)
    pub(crate) fn settle(mut self) -> i64 {
        let link = self.inode.private::<BpfCgroupLinkInode>()
            .expect("BPF cgroup primer inode");
        link.attached.store(true, Ordering::Release);
        settle_cgroup_link_id(self.id, &self.inode);
        self.fdt.fd_install(self.fd, Arc::clone(&self.file));
        self.settled = true;
        self.fd as i64
    }
}

impl Drop for BpfCgroupLinkPrimer {
    fn drop(&mut self) {
        if !self.settled {
            cancel_cgroup_link_id(self.id);
            self.fdt.put_unused_fd(self.fd);
        }
    }
}

/// Reserve the caller's fd before reserving an unsettled link ID.
/// # C: O(fd words + log links)
pub(crate) fn prime_bpf_cgroup_link(
    cgid: u64,
    attach_type: cgroup::CgroupBpfAttachType,
    prog: InodeRef,
) -> Result<BpfCgroupLinkPrimer, Errno> {
    let cur = sched::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; preempt-off on syscall path; table is pinned.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    prime_bpf_cgroup_link_with(fdt, cur.nofile_soft(), cgid, attach_type, prog)
}

pub(crate) fn prime_bpf_cgroup_link_with(
    fdt: Arc<vfs::FdTable>,
    limit: usize,
    cgid: u64,
    attach_type: cgroup::CgroupBpfAttachType,
    prog: InodeRef,
) -> Result<BpfCgroupLinkPrimer, Errno> {
    use vfs::{File, OpenFlags};
    let fd = fdt.get_unused_fd_flags(OpenFlags::O_CLOEXEC, limit)
        .map_err(|_| Errno::Emfile)?;
    let id = reserve_cgroup_link_id();
    let inode = make_bpf_cgroup_link_inode(BpfCgroupLinkInode {
        id, cgid, attach_type, _prog: prog, attached: AtomicBool::new(false),
    });
    let dentry = vfs::dcache::d_alloc_pseudo(
        "bpf-link", Arc::clone(&inode), &crate::anon_dname::ANON_INODE_OPS,
    );
    let file = File::new(Arc::clone(&inode), dentry, OpenFlags::O_RDWR);
    Ok(BpfCgroupLinkPrimer { id, fd, fdt, file, inode, settled: false })
}
