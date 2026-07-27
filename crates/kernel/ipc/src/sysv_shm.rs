// SysV shared memory registry per `24`: Linux-shaped shmget key/create
// semantics, shmem-backed shared mappings for shmat, and the shmctl/shmdt
// lifecycle hooks currently implemented by the syscall surface.

#![allow(dead_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};
use namespace_identity::NamespaceId;

use sync::{Spinlock, TaskList as ShmLockClass};

mod shmctl;
mod shmdt;
pub use self::shmctl::sys_shmctl;
pub use self::shmdt::sys_shmdt;

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_MODE_MASK: u64 = 0o777;
const IPC_PERM_BITS: u32 = 0o7;
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
    /// The shared shmem backing (one anon-tmpfs inode). Created by the syscalls
    /// shim (which can reach tmpfs); the ipc registry only holds + maps it.
    pub backing: Arc<dyn vmm::FileBacking>,
}

#[derive(Clone)]
pub(super) struct IpcCred {
    pub(super) euid: u32,
    pub(super) egid: u32,
    pub(super) groups: [u32; sched::Creds::NGROUPS_V1],
    pub(super) ngroups: usize,
    pub(super) cap_ipc_owner: bool,
    pub(super) cap_ipc_lock: bool,
    pub(super) cap_sys_admin: bool,
}

pub(super) fn current_ipc_cred() -> IpcCred {
    use core::sync::atomic::Ordering;
    let mut out = IpcCred {
        euid: 0,
        egid: 0,
        groups: [0; sched::Creds::NGROUPS_V1],
        ngroups: 0,
        cap_ipc_owner: true,
        cap_ipc_lock: true,
        cap_sys_admin: true,
    };
    if let Some(t) = sched::current() {
        out.euid = t.creds.euid.load(Ordering::Acquire);
        out.egid = t.creds.egid.load(Ordering::Acquire);
        out.cap_ipc_owner = t.has_cap(sched::cap::IPC_OWNER);
        out.cap_ipc_lock = t.has_cap(sched::cap::IPC_LOCK);
        out.cap_sys_admin = t.has_cap(sched::cap::SYS_ADMIN);
        let n = t.creds.ngroups.load(Ordering::Acquire) as usize;
        out.ngroups = n.min(sched::Creds::NGROUPS_V1);
        // SAFETY: supplementary groups are mutated only by the running task's credential syscall path; snapshot tolerates a stale concurrent value.
        unsafe {
            let src = &*t.creds.groups.get();
            out.groups[..out.ngroups].copy_from_slice(&src[..out.ngroups]);
        }
    }
    out
}

fn in_group(cred: &IpcCred, gid: u32) -> bool {
    cred.egid == gid || cred.groups[..cred.ngroups].contains(&gid)
}

pub(super) fn ipc_permitted(seg: &ShmSegment, cred: &IpcCred, flg: u64) -> bool {
    let req = (((flg >> 6) | (flg >> 3) | flg) as u32) & IPC_PERM_BITS;
    let mut granted = seg.mode;
    if cred.euid == seg.cuid || cred.euid == seg.uid {
        granted >>= 6;
    } else if in_group(cred, seg.cgid) || in_group(cred, seg.gid) {
        granted >>= 3;
    }
    (req & !granted & IPC_PERM_BITS) == 0 || cred.cap_ipc_owner
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
/// # C: O(N_segments)
pub(super) fn lookup_segment_by_backing(backing: &Arc<dyn vmm::FileBacking>) -> Option<Arc<ShmSegment>> {
    let owner = crate::ipc_namespace::current().ok()?;
    let ns = owner.key();
    let want = self::shmdt::backing_addr(backing);
    let g = REG.segs.lock();
    g.iter().find(|s| s.ns == ns && self::shmdt::backing_addr(&s.backing) == want).cloned()
}

/// Linux `shm_close` accounting: one attachment went away. A segment whose
/// `IPC_RMID` already set `SHM_DEST` is destroyed by the last detach — until
/// then `rmid_segment` only marks it, so an existing attacher keeps working
/// exactly as it does on Linux.
/// # C: O(N_segments)
pub(super) fn release_detached(seg: &Arc<ShmSegment>) {
    let left = seg.nattch.fetch_sub(1, Ordering::AcqRel) - 1;
    if left > 0 { return; }
    let mut g = REG.segs.lock();
    if let Some(pos) = g.iter().position(|s| Arc::ptr_eq(s, seg)) {
        if (g[pos].mode & SHM_DEST) != 0 && g[pos].nattch.load(Ordering::Acquire) <= 0 {
            g.remove(pos);
        }
    }
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
    let hint = match plan.addr {
        Some(a) => match hal::UserVirtAddr::new(a) {
            Some(u) => Some(u), None => return -(Errno::Einval.as_i32() as i64),
        },
        None => None,
    };
    let res = mm.mmap(
        hint, plan.len,
        plan.prot,
        VmaFlags::SHARED | VmaFlags::ANONYMOUS,
        VmaBacking::File { backing: seg.backing.clone(), off: 0 },
        plan.fixed,
    );
    match res {
        Ok(va)  => {
            seg.nattch.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
            va.as_u64() as i64
        }
        Err(e)  => {
            let eno = errno_from_vmm(e);
            -(eno.as_i32() as i64)
        }
    }
}

#[cfg(test)]
mod tests;
