// SysV shared memory registry per `24`: Linux-shaped shmget key/create
// semantics, shmem-backed shared mappings for shmat, and the shmctl/shmdt
// lifecycle hooks currently implemented by the syscall surface.

#![allow(dead_code)]

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};
use namespace_identity::NamespaceId;

use sync::{Spinlock, TaskList as ShmLockClass};

// Module manifest:
//   rules        — pure `shm_may_destroy` / creator-exit destroy predicate
//   creator      — `shm_creator` back-reference + `exit_shm`
//   rmid_forced  — `kernel.shm_rmid_forced` per-namespace flag + orphan sweep
//   shmctl       — `shmctl(2)` commands
//   shmdt        — `shmdt(2)` attachment geometry
pub mod creator;
pub mod rmid_forced;
pub mod rules;
mod shmctl;
mod shmdt;
pub use self::creator::exit_shm;
pub use self::rmid_forced::{set_shm_rmid_forced, shm_rmid_forced, RMID_FORCED_BOUNDS};
pub use self::shmctl::sys_shmctl;
pub use self::shmdt::sys_shmdt;

pub(super) const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_MODE_MASK: u64 = 0o777;
const SHM_HUGETLB: u64 = 0o4000;
const SHM_RDONLY: u64 = 0o10000;
const SHM_RND: u64 = 0o20000;
const SHM_REMAP: u64 = 0o40000;
const SHM_EXEC: u64 = 0o100000;
pub(super) const SHM_DEST: u32 = 0o1000;
pub(super) const SHM_LOCKED: u32 = 0o2000;
const SHMLBA: u64 = PAGE_SIZE;
const S_IRUGO: u64 = 0o444;
const S_IWUGO: u64 = 0o222;
const S_IXUGO: u64 = 0o111;

pub(super) const PAGE_SIZE: u64 = 4096;
const SHM_MIN_SIZE: usize = 1;
pub(super) const SHMMNI: usize = 4096;
pub(super) const SHM_MAX_SIZE: usize = usize::MAX - (1 << 24);

/// One SysV shm segment. Backed by a single shared shmem (anonymous tmpfs)
/// object — every `shmat` maps THIS object MAP_SHARED, so all attaches (and
/// their forked children) share the same physical frames and see each other's
/// writes (real Linux SysV shm), instead of each getting a private copy.
pub struct ShmSegment {
    pub id:    i32,
    pub key:   i32,
    /// Internal table key derived from the canonical IPC namespace owner.
    pub ns:    NamespaceId,
    pub size:  usize,
    pub mode:  u32,
    pub uid:   u32,
    pub gid:   u32,
    pub cuid:  u32,
    pub cgid:  u32,
    /// Creator PID (shm_cpid) for IPC_STAT.
    pub cpid:  u32,
    /// Current attach count (shm_nattch); bumped on shmat.
    pub nattch: core::sync::atomic::AtomicI64,
    /// `shm_creator`: the task that created this segment, cleared by
    /// `exit_shm` when that task dies. `None` therefore means "orphaned" —
    /// the state `kernel.shm_rmid_forced`'s sweep selects on (`creator.rs`).
    pub creator: Spinlock<Option<Weak<sched::Task>>, ShmLockClass>,
    /// The shared shmem backing (one anon-tmpfs inode). Created by the syscalls
    /// shim (which can reach tmpfs); the ipc registry only holds + maps it.
    pub backing: Arc<dyn vmm::FileBacking>,
}

/// Credentials and the permission algebra are shared with sem and msg — Linux
/// has one `ipcperms()` for all three classes, and a private copy here is how
/// the classes drift. `ShmSegment` keeps its ids inline rather than in an
/// `IpcPerm`, so it calls the loose-field form.
pub(super) use crate::sysv::perm::{current_ipc_cred, IpcCred};

/// # C: O(log n)
pub(super) fn ipc_permitted(seg: &ShmSegment, cred: &IpcCred, flg: u64) -> bool {
    crate::sysv::perm::ipc_permitted_fields(
        seg.mode, seg.uid, seg.gid, seg.cuid, seg.cgid, cred, flg as i32)
}

fn valid_new_size(size: usize) -> bool {
    if size < SHM_MIN_SIZE || size > SHM_MAX_SIZE { return false; }
    size.checked_add((PAGE_SIZE - 1) as usize).is_some()
}

pub(super) struct ShmRegistry {
    next_id: AtomicI32,
    segs: Spinlock<Vec<Arc<ShmSegment>>, ShmLockClass>,
}

pub(super) static REG: ShmRegistry = ShmRegistry {
    next_id: AtomicI32::new(1),
    segs: Spinlock::new(Vec::new()),
};

pub(crate) fn reap_namespace(ns: NamespaceId) {
    REG.segs.lock().retain(|segment| segment.ns != ns);
    self::rmid_forced::reap_namespace(ns);
}

/// `shmget` registry entry. The syscalls shim passes a lazy `make_backing`
/// closure because Linux allocates shmem only on the create path.
/// # C: O(N_segments) on lookup
pub fn shmget_with_backing<F>(key: i32, size: usize, flg: u64, cpid: u32, make_backing: F) -> i64
where F: FnOnce() -> Arc<dyn vmm::FileBacking> {
    shmget_with_backing_cred(key, size, flg, cpid, current_ipc_cred(), make_backing)
}

fn shmget_with_backing_cred<F>(
    key: i32, size: usize, flg: u64, cpid: u32, cred: IpcCred, make_backing: F,
) -> i64
where F: FnOnce() -> Arc<dyn vmm::FileBacking> {
    use syscall::errno::Errno;
    let owner = match crate::ipc_namespace::current() {
        Ok(owner) => owner, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let ns = owner.key();
    if key != IPC_PRIVATE {
        let g = REG.segs.lock();
        for s in g.iter() {
            if s.key == key && s.ns == ns {
                if flg & IPC_CREAT != 0 && flg & IPC_EXCL != 0 {
                    return -(Errno::Eexist.as_i32() as i64);
                }
                if s.size < size {
                    return -(Errno::Einval.as_i32() as i64);
                }
                if !ipc_permitted(s, &cred, flg) {
                    return -(Errno::Eacces.as_i32() as i64);
                }
                return s.id as i64;
            }
        }
        if flg & IPC_CREAT == 0 {
            return -(Errno::Enoent.as_i32() as i64);
        }
    }
    if !valid_new_size(size) {
        return -(Errno::Einval.as_i32() as i64);
    }
    if flg & SHM_HUGETLB != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mut g = REG.segs.lock();
    if g.iter().filter(|s| s.ns == ns).count() >= SHMMNI {
        return -(Errno::Enospc.as_i32() as i64);
    }
    let id = REG.next_id.fetch_add(1, Ordering::AcqRel);
    let seg = Arc::new(ShmSegment {
        id, key, ns, size,
        mode: (flg & IPC_MODE_MASK) as u32,
        uid: cred.euid,
        gid: cred.egid,
        cuid: cred.euid,
        cgid: cred.egid,
        cpid,
        nattch: core::sync::atomic::AtomicI64::new(0),
        creator: Spinlock::new(self::creator::current_creator()),
        backing: make_backing(),
    });
    g.push(seg);
    id as i64
}

pub(super) fn lookup_by_id(id: i32) -> Option<Arc<ShmSegment>> {
    let owner = crate::ipc_namespace::current().ok()?;
    let ns = owner.key();
    let g = REG.segs.lock();
    g.iter().find(|s| s.id == id && s.ns == ns).cloned()
}

#[derive(Copy, Clone, Debug)]
struct ShmatPlan {
    addr: Option<u64>,
    len: usize,
    prot: vmm::VmaProt,
    fixed: bool,
}

pub(super) fn page_align_len(size: usize) -> Option<usize> {
    size.checked_add((PAGE_SIZE - 1) as usize).map(|v| v & !((PAGE_SIZE - 1) as usize))
}

/// The registered segment (in the caller's IPC namespace) whose shmem object
/// is `backing`, if any. `shmdt` uses this to tell a shm attachment apart from
/// every other file-backed VMA.
/// Identify a segment from the backing object one of its VMAs carries. The
/// backing pointer IS the identity (Linux matches `vma->vm_file`), so there is
/// no namespace filter: a task that entered a new IPC namespace still holds and
/// must still be able to detach the attachment it made in the old one, and the
/// `vm_ops` callbacks below run during address-space teardown where the
/// exiting task's namespace is not a meaningful question.
/// # C: O(N_segments)
pub(super) fn lookup_segment_by_backing(backing: &Arc<dyn vmm::FileBacking>) -> Option<Arc<ShmSegment>> {
    let want = self::shmdt::backing_addr(backing);
    let g = REG.segs.lock();
    g.iter().find(|s| self::shmdt::backing_addr(&s.backing) == want).cloned()
}

/// Linux `shm_open` (`ipc/shm.c` `shm_vm_ops.open`): a new VMA references this
/// segment — `shmat`'s own mmap, a fork copy, or a fragment of a split.
/// # C: O(N_segments)
pub fn shm_vma_open(backing: &Arc<dyn vmm::FileBacking>) {
    if let Some(seg) = lookup_segment_by_backing(backing) {
        seg.nattch.fetch_add(1, Ordering::AcqRel);
    }
}

/// Linux `shm_close` (`ipc/shm.c` `shm_vm_ops.close`): one VMA referencing
/// this segment is gone. The last one destroys a segment already marked
/// `SHM_DEST`.
/// # C: O(N_segments)
pub fn shm_vma_close(backing: &Arc<dyn vmm::FileBacking>) {
    if let Some(seg) = lookup_segment_by_backing(backing) { release_detached(&seg); }
}

/// Linux `shm_close` accounting: one attachment went away, and the segment is
/// destroyed if `shm_may_destroy` now holds — either `IPC_RMID` already set
/// `SHM_DEST` (until the last detach `rmid_segment` only marks it, so an
/// existing attacher keeps working exactly as it does on Linux) or the
/// namespace forces reclaim. Also Linux's `out_nattch` tail: the guard
/// reference `sys_shmat` takes across its mmap is released through here.
/// # C: O(N_segments)
pub(super) fn release_detached(seg: &Arc<ShmSegment>) {
    let left = seg.nattch.fetch_sub(1, Ordering::AcqRel) - 1;
    if left > 0 { return; }
    let forced = self::rmid_forced::is_forced(seg.ns);
    // The last reference is dropped OUTSIDE the registry lock: this runs from
    // `shm_vma_close` with the address space's VMA lock held, and destroying
    // the backing object under a second lock is how lock orders get invented.
    let doomed = {
        let mut g = REG.segs.lock();
        match g.iter().position(|s| Arc::ptr_eq(s, seg)) {
            Some(pos) if self::rules::shm_may_destroy(
                g[pos].nattch.load(Ordering::Acquire), forced, g[pos].mode) => Some(g.remove(pos)),
            _ => None,
        }
    };
    drop(doomed);
}

fn shmat_addr(shmaddr: u64, shmflg: u64) -> Result<Option<u64>, syscall::errno::Errno> {
    use syscall::errno::Errno;
    if shmaddr != 0 {
        let mut addr = shmaddr;
        if (addr & (SHMLBA - 1)) != 0 {
            if (shmflg & SHM_RND) == 0 { return Err(Errno::Einval); }
            addr &= !(SHMLBA - 1);
            if addr == 0 && (shmflg & SHM_REMAP) != 0 { return Err(Errno::Einval); }
        }
        Ok(Some(addr))
    } else if (shmflg & SHM_REMAP) != 0 {
        Err(Errno::Einval)
    } else {
        Ok(None)
    }
}

fn shmat_prot_access(shmflg: u64) -> (vmm::VmaProt, u64) {
    let (mut prot, mut acc_mode) = if (shmflg & SHM_RDONLY) != 0 {
        (vmm::VmaProt::READ, S_IRUGO)
    } else {
        (vmm::VmaProt::READ | vmm::VmaProt::WRITE, S_IRUGO | S_IWUGO)
    };
    if (shmflg & SHM_EXEC) != 0 {
        prot |= vmm::VmaProt::EXEC;
        acc_mode |= S_IXUGO;
    }
    (prot, acc_mode)
}

fn shmat_plan(
    seg: &ShmSegment, cred: &IpcCred, shmaddr: u64, shmflg: u64, overlaps: bool,
) -> Result<ShmatPlan, syscall::errno::Errno> {
    use syscall::errno::Errno;
    let addr = shmat_addr(shmaddr, shmflg)?;
    let (prot, acc_mode) = shmat_prot_access(shmflg);
    if !ipc_permitted(seg, cred, acc_mode) { return Err(Errno::Eacces); }
    let len = page_align_len(seg.size).ok_or(Errno::Enomem)?;
    if let Some(a) = addr {
        let end = a.checked_add(len as u64).ok_or(Errno::Einval)?;
        if end > hal::USER_VA_END { return Err(Errno::Einval); }
        if (shmflg & SHM_REMAP) == 0 && overlaps { return Err(Errno::Einval); }
    }
    Ok(ShmatPlan { addr, len, prot, fixed: addr.is_some() && (shmflg & SHM_REMAP) != 0 })
}

fn shmat_range_overlaps(mm: &vmm::AddressSpace, addr: u64, len: usize) -> bool {
    let end = addr.saturating_add(len as u64);
    mm.snapshot_vmas().iter().any(|v| v.start.as_u64() < end && v.end.as_u64() > addr)
}

fn errno_from_vmm(e: vmm::Error) -> syscall::errno::Errno {
    match e {
        vmm::Error::Inval => syscall::errno::Errno::Einval,
        vmm::Error::Access => syscall::errno::Errno::Eacces,
        vmm::Error::Perm => syscall::errno::Errno::Eperm,
        vmm::Error::Fault => syscall::errno::Errno::Efault,
        vmm::Error::Again => syscall::errno::Errno::Eagain,
        vmm::Error::Io => syscall::errno::Errno::Eio,
        vmm::Error::NotImplemented => syscall::errno::Errno::Enosys,
        vmm::Error::NoMem => syscall::errno::Errno::Enomem,
    }
}

/// `shmat(shmid, shmaddr, shmflg)` — slot 30.
/// # C: O(N_segments) lookup
pub fn sys_shmat(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    use vmm::{VmaFlags, VmaBacking};
    let shmid = args.a0 as i32;
    let addr = args.a1;
    let flg  = args.a2;
    let seg = match lookup_by_id(shmid) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = match unsafe { cur.mm_ref() } {
        Some(m) => m.clone(), None => return -(Errno::Einval.as_i32() as i64),
    };
    let cred = current_ipc_cred();
    let first = match shmat_plan(&seg, &cred, addr, flg, false) {
        Ok(p) => p,
        Err(e) => return -(e.as_i32() as i64),
    };
    let overlaps = first.addr.map(|a| (flg & SHM_REMAP) == 0 && shmat_range_overlaps(&mm, a, first.len)).unwrap_or(false);
    let plan = match if overlaps { shmat_plan(&seg, &cred, addr, flg, true) } else { Ok(first) } {
        Ok(p) => p,
        Err(e) => return -(e.as_i32() as i64),
    };
    let mut final_prot = plan.prot;
    // Linux shmat reaches do_mmap after ipcperms; READ_IMPLIES_EXEC therefore
    // applies before MDWE even when userspace did not pass SHM_EXEC.
    if final_prot.contains(vmm::VmaProt::READ)
        && sched::personality::read_implies_exec(&cur)
    {
        final_prot |= vmm::VmaProt::EXEC;
    }
    let hint = match plan.addr {
        Some(a) => match hal::UserVirtAddr::new(a) {
            Some(u) => Some(u), None => return -(Errno::Einval.as_i32() as i64),
        },
        None => None,
    };
    // Linux `do_shmat` bumps `shm_nattch` BEFORE `do_mmap` and drops that
    // guard reference at `out_nattch`. Without it a concurrent `IPC_RMID`
    // seeing `nattch == 0` destroys the segment between the lookup above and
    // the mapping below, and the attachment that lands afterwards is counted
    // against a segment no longer in the registry — invisible to `shmdt` and
    // never reclaimed.
    seg.nattch.fetch_add(1, Ordering::AcqRel);
    let res = mm.mmap(
        hint, plan.len,
        final_prot,
        // `SYSVSHM` is this kernel's `vma->vm_ops == &shm_vm_ops`: it is what
        // makes `shm_nattch` follow VMA lifetime through fork, split and
        // address-space teardown instead of only shmat/shmdt, and the mmap
        // below is the `vm_ops->open` that counts THIS attachment.
        VmaFlags::SHARED | VmaFlags::ANONYMOUS | VmaFlags::SYSVSHM,
        VmaBacking::File { backing: seg.backing.clone(), off: 0 },
        plan.fixed,
    );
    release_detached(&seg);
    match res {
        Ok(va)  => va.as_u64() as i64,
        Err(e)  => {
            let eno = errno_from_vmm(e);
            -(eno.as_i32() as i64)
        }
    }
}

#[cfg(test)]
pub(crate) mod test_claim;

#[cfg(test)]
mod tests;
