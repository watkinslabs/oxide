// Link objects: fd-backed cgroup and LSM links, plus the link id registry
// and the two-phase publication that keeps an id unobservable until the
// attachment behind it exists.

extern crate alloc;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use syscall::errno::Errno;
use vfs::{FileType, InodeRef, InodeBuilder, default_inode_ops, default_file_ops, mk_mode};

use super::{BPF_FD_MODE, ids};

#[path = "link/registry.rs"]
mod registry;
pub(crate) use registry::{
    cancel_link_id, link_by_id, next_live_link_id, reserve_link_id, settle_link_id,
};

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

/// Build the `Arc<Inode>` for a BPF LSM link fd, and give it a link id in
/// the same registry the cgroup links use — one id space for every link
/// kind, so an LSM link is reachable by LINK_GET_FD_BY_ID and appears in
/// a LINK_GET_NEXT_ID walk. The object and its hook registration come
/// into being together, so the id needs no reservation window. # C: O(log links)
pub fn make_bpf_lsm_link_inode(link: BpfLsmLinkInode) -> InodeRef {
    let inode = InodeBuilder::new(ids::INO_LINK, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .private(Arc::new(link))
        .build();
    registry::publish_link_id(&inode);
    inode
}

/// fd-backed cgroup link. The cgroup hierarchy owns attachment state; the
/// link pins its program and removes that exact entry on final close.
pub struct BpfCgroupLinkInode {
    pub(super) id: u32,
    pub(super) cgid: u64,
    pub(super) attach_type: cgroup::CgroupBpfAttachType,
    /// The program this link runs. Linux keeps it on the link and lets
    /// the effective arrays derive from it, so LINK_UPDATE swaps this and
    /// the cgroup entry together rather than leaving two answers.
    prog: Spinlock<InodeRef, TaskListClass>,
    attached: AtomicBool,
}

impl BpfCgroupLinkInode {
    /// Program currently attached through this link. # C: O(1)
    pub(crate) fn prog(&self) -> InodeRef { Arc::clone(&*self.prog.lock()) }

    /// `cgroup_bpf_replace()`: swap the program this link runs, keeping
    /// its position in the cgroup's direct list. A link whose attachment
    /// is already released is `-ENOLINK`; a caller naming the wrong
    /// currently-attached program is `-EPERM`.
    /// # C: O(descendants * effective programs)
    pub(crate) fn replace_prog(
        &self,
        new_prog: InodeRef,
        expect: Option<&InodeRef>,
    ) -> Result<i64, Errno> {
        let mut current = self.prog.lock();
        if !self.attached.load(Ordering::Acquire) { return Err(Errno::Enolink); }
        if let Some(expect) = expect {
            if !Arc::ptr_eq(&*current, expect) { return Err(Errno::Eperm); }
        }
        cgroup::bpf::replace_link(
            self.cgid, self.attach_type, self.id as u64,
            Arc::clone(&new_prog), Some(&*current),
        ).map_err(replace_error)?;
        *current = new_prog;
        Ok(0)
    }

    /// `BPF_LINK_DETACH`: drop the cgroup attachment while the descriptor
    /// stays open. The id remains resolvable — a detached link is still a
    /// live object — and a second detach is a no-op success, matching a
    /// link whose cgroup went away underneath it. # C: O(descendants * programs)
    pub(crate) fn detach(&self) -> Result<i64, Errno> {
        if self.attached.swap(false, Ordering::AcqRel) {
            let _ = cgroup::bpf::detach_link(self.cgid, self.attach_type, self.id as u64);
        }
        Ok(0)
    }
}

impl Drop for BpfCgroupLinkInode {
    fn drop(&mut self) {
        if self.attached.load(Ordering::Acquire) {
            let _ = cgroup::bpf::detach_link(self.cgid, self.attach_type, self.id as u64);
        }
        registry::forget_link_id(self.id);
    }
}

/// Build an unsettled cgroup BPF link fd inode. # C: O(1)
pub fn make_bpf_cgroup_link_inode(link: BpfCgroupLinkInode) -> InodeRef {
    InodeBuilder::new(ids::INO_LINK, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .private(Arc::new(link))
        .build()
}

/// Direct-list outcomes the replace path can produce. `Missing` means the
/// link has no entry in the list it believed it owned.
fn replace_error(error: cgroup::BpfAttachError) -> Errno {
    match error {
        cgroup::BpfAttachError::Offline | cgroup::BpfAttachError::Missing => Errno::Enolink,
        cgroup::BpfAttachError::Denied => Errno::Eperm,
        _ => Errno::Einval,
    }
}

/// Resolve a settled link by id, for the cgroup ordering anchors that
/// name a link by `BPF_F_ID`. The caller re-checks the kind.
/// # C: O(log links)
pub(crate) fn cgroup_link_by_id(id: u32) -> Result<InodeRef, Errno> { link_by_id(id) }

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
        settle_link_id(self.id, &self.inode);
        self.fdt.fd_install(self.fd, Arc::clone(&self.file));
        self.settled = true;
        self.fd as i64
    }
}

impl Drop for BpfCgroupLinkPrimer {
    fn drop(&mut self) {
        if !self.settled {
            cancel_link_id(self.id);
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
    let id = reserve_link_id();
    let inode = make_bpf_cgroup_link_inode(BpfCgroupLinkInode {
        id, cgid, attach_type, prog: Spinlock::new(prog),
        attached: AtomicBool::new(false),
    });
    let dentry = vfs::dcache::d_alloc_pseudo(
        "bpf-link", Arc::clone(&inode), &crate::anon_dname::ANON_INODE_OPS,
    );
    let file = File::new(Arc::clone(&inode), dentry, OpenFlags::O_RDWR);
    Ok(BpfCgroupLinkPrimer { id, fd, fdt, file, inode, settled: false })
}
