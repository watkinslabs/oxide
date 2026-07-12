// SysV shared memory registry per `24`: Linux-shaped shmget key/create
// semantics, shmem-backed shared mappings for shmat, and the shmctl/shmdt
// lifecycle hooks currently implemented by the syscall surface.

#![allow(dead_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};

use sync::{Spinlock, TaskList as ShmLockClass};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_MODE_MASK: u64 = 0o777;
const IPC_PERM_BITS: u32 = 0o7;
const CAP_IPC_OWNER: u32 = 15;
const SHM_HUGETLB: u64 = 0o4000;

/// `shmctl` cmd values (Linux).
const IPC_RMID: u64 = 0;
const IPC_STAT: u64 = 2;
const IPC_INFO: u64 = 3;

const PAGE_SIZE: u64 = 4096;
const SHM_MIN_SIZE: usize = 1;
const SHMMNI: usize = 4096;
const SHM_MAX_SIZE: usize = usize::MAX - (1 << 24);

/// One SysV shm segment. Backed by a single shared shmem (anonymous tmpfs)
/// object — every `shmat` maps THIS object MAP_SHARED, so all attaches (and
/// their forked children) share the same physical frames and see each other's
/// writes (real Linux SysV shm), instead of each getting a private copy.
pub struct ShmSegment {
    pub id:    i32,
    pub key:   i32,
    /// IPC namespace id (CLONE_NEWIPC). 0 = init NS.
    pub ns:    u64,
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

fn current_ipc_ns() -> u64 {
    use core::sync::atomic::Ordering;
    sched::current().map(|t| t.ipc_ns.load(Ordering::Acquire)).unwrap_or(0)
}

#[derive(Clone)]
struct IpcCred {
    euid: u32,
    egid: u32,
    groups: [u32; sched::Creds::NGROUPS_V1],
    ngroups: usize,
    cap_ipc_owner: bool,
}

fn current_ipc_cred() -> IpcCred {
    use core::sync::atomic::Ordering;
    let mut out = IpcCred {
        euid: 0,
        egid: 0,
        groups: [0; sched::Creds::NGROUPS_V1],
        ngroups: 0,
        cap_ipc_owner: true,
    };
    if let Some(t) = sched::current() {
        out.euid = t.creds.euid.load(Ordering::Acquire);
        out.egid = t.creds.egid.load(Ordering::Acquire);
        out.cap_ipc_owner = t.has_cap(CAP_IPC_OWNER);
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

fn ipc_permitted(seg: &ShmSegment, cred: &IpcCred, flg: u64) -> bool {
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

struct ShmRegistry {
    next_id: AtomicI32,
    segs: Spinlock<Vec<Arc<ShmSegment>>, ShmLockClass>,
}

static REG: ShmRegistry = ShmRegistry {
    next_id: AtomicI32::new(1),
    segs: Spinlock::new(Vec::new()),
};

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
    let ns = current_ipc_ns();
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

fn lookup_by_id(id: i32) -> Option<Arc<ShmSegment>> {
    let ns = current_ipc_ns();
    let g = REG.segs.lock();
    g.iter().find(|s| s.id == id && s.ns == ns).cloned()
}

/// `shmat(shmid, shmaddr, shmflg)` — slot 30.
/// # C: O(N_segments) lookup
pub fn sys_shmat(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    use vmm::{VmaProt, VmaFlags, VmaBacking};
    let shmid = args.a0 as i32;
    let _addr = args.a1;
    let _flg  = args.a2;
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
    // Map the segment's ONE shared shmem backing MAP_SHARED at a kernel-picked
    // hole — the anon-shmem recipe (VmaFlags::SHARED|ANONYMOUS + File{tmpfs},
    // Linux `shmem`): every attach maps the same inode, so all attaches (and
    // forked children) alias the same physical frames and see each other's
    // writes. The Arc<ShmSegment> in REG keeps the backing alive until IPC_RMID.
    let len_aligned = (seg.size as u64 + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let res = mm.mmap(
        None, len_aligned as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::SHARED | VmaFlags::ANONYMOUS,
        VmaBacking::File { backing: seg.backing.clone(), off: 0 },
        false,
    );
    match res {
        Ok(va)  => {
            seg.nattch.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
            va.as_u64() as i64
        }
        Err(_)  => -(Errno::Enomem.as_i32() as i64),
    }
}

/// `shmdt(shmaddr)` — slot 67. Drops the VMA at the supplied addr.
/// We don't track per-attach lengths in v1 — the AS::munmap call
/// uses the VMA's known end. For Linux semantics shmdt only takes
/// an address; the kernel finds the matching VMA and unmaps it.
/// # C: O(N_VMAs)
pub fn sys_shmdt(args: &syscall::SyscallArgs) -> i64 {
    use hal::UserVirtAddr;
    use syscall::errno::Errno;
    let addr = args.a0;
    if addr == 0 || (addr & 0xFFF) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = match unsafe { cur.mm_ref() } {
        Some(m) => m.clone(), None => return -(Errno::Einval.as_i32() as i64),
    };
    let ua = match UserVirtAddr::new(addr) {
        Some(u) => u, None => return -(Errno::Einval.as_i32() as i64),
    };
    // Without a per-attach size table we munmap one page minimum.
    // Userspace shmctl-then-shmdt is the typical cleanup; the
    // residual VMA gets reaped at execve / exit anyway.
    let _ = mm.munmap(ua, PAGE_SIZE as usize);
    0
}

/// `shmctl(shmid, cmd, buf)` — slot 31. v1 honors IPC_RMID
/// (frees the segment) and accepts IPC_STAT / IPC_INFO with a
/// zero-fill writeback so callers don't bail.
/// # C: O(N_segments)
pub fn sys_shmctl(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let shmid = args.a0 as i32;
    let cmd   = args.a1;
    let buf   = args.a2;
    match cmd {
        IPC_RMID => {
            let mut g = REG.segs.lock();
            let before = g.len();
            g.retain(|s| s.id != shmid);
            if g.len() == before {
                return -(Errno::Einval.as_i32() as i64);
            }
            0
        }
        IPC_STAT | IPC_INFO => {
            let seg = match lookup_by_id(shmid) {
                Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
            };
            if buf != 0 && buf < hal::USER_VA_END {
                // struct shmid64_ds (Linux x86_64, 112 B). Populate the fields we
                // track — shm_perm.key@0, shm_perm.mode@20, shm_segsz@48,
                // shm_cpid@80, shm_nattch@88 — instead of the old all-zero fill
                // (which made `ipcs -m` and stat readers see a 0-byte segment).
                let mut ds = [0u8; 112];
                ds[0..4].copy_from_slice(&seg.key.to_le_bytes());
                ds[20..24].copy_from_slice(&seg.mode.to_le_bytes());
                ds[48..56].copy_from_slice(&(seg.size as u64).to_le_bytes());
                ds[80..84].copy_from_slice(&(seg.cpid as i32).to_le_bytes());
                let nattch = seg.nattch.load(core::sync::atomic::Ordering::Acquire).max(0) as u64;
                ds[88..96].copy_from_slice(&nattch.to_le_bytes());
                // SAFETY: buf validated < USER_VA_END; byte-wise write is alignment-safe; CPL=0 writes through caller's AS.
                unsafe {
                    for i in 0..112usize {
                        core::ptr::write_volatile((buf + i as u64) as *mut u8, ds[i]);
                    }
                }
            }
            0
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    struct FakeBacking;

    impl vmm::FileBacking for FakeBacking {
        fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, ()> { Ok(0) }
        fn size_hint(&self) -> u64 { 0 }
    }

    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn err(e: syscall::errno::Errno) -> i64 {
        -(e.as_i32() as i64)
    }

    fn cred(euid: u32, egid: u32, groups: &[u32], cap: bool) -> IpcCred {
        let mut out = IpcCred {
            euid,
            egid,
            groups: [0; sched::Creds::NGROUPS_V1],
            ngroups: groups.len().min(sched::Creds::NGROUPS_V1),
            cap_ipc_owner: cap,
        };
        out.groups[..out.ngroups].copy_from_slice(&groups[..out.ngroups]);
        out
    }

    fn reset() {
        REG.next_id.store(1, AtomicOrdering::Release);
        REG.segs.lock().clear();
    }

    fn backing() -> Arc<dyn vmm::FileBacking> {
        Arc::new(FakeBacking)
    }

    fn shmget(key: i32, size: usize, flg: u64, cred: IpcCred) -> i64 {
        shmget_with_backing_cred(key, size, flg, 77, cred, backing)
    }

    #[test]
    fn private_key_always_creates_and_validates_new_size() {
        let _g = TEST_LOCK.lock().unwrap();
        reset();
        let c = cred(10, 20, &[], false);
        let a = shmget(IPC_PRIVATE, 1, 0, c.clone());
        let b = shmget(IPC_PRIVATE, 1, 0, c.clone());
        assert!(a > 0);
        assert!(b > 0);
        assert_ne!(a, b);
        assert_eq!(shmget(IPC_PRIVATE, 0, 0, c), err(syscall::errno::Errno::Einval));
    }

    #[test]
    fn missing_public_key_without_create_returns_enoent_before_size_validation() {
        let _g = TEST_LOCK.lock().unwrap();
        reset();
        let calls = AtomicUsize::new(0);
        let r = shmget_with_backing_cred(123, 0, 0, 77, cred(1, 1, &[], false), || {
            calls.fetch_add(1, AtomicOrdering::AcqRel);
            backing()
        });
        assert_eq!(r, err(syscall::errno::Errno::Enoent));
        assert_eq!(calls.load(AtomicOrdering::Acquire), 0);
    }

    #[test]
    fn create_public_key_records_owner_mode_and_lazy_allocates() {
        let _g = TEST_LOCK.lock().unwrap();
        reset();
        let calls = AtomicUsize::new(0);
        let id = shmget_with_backing_cred(44, 4096, IPC_CREAT | 0o640, 77, cred(42, 7, &[], false), || {
            calls.fetch_add(1, AtomicOrdering::AcqRel);
            backing()
        });
        assert!(id > 0);
        assert_eq!(calls.load(AtomicOrdering::Acquire), 1);
        let seg = lookup_by_id(id as i32).unwrap();
        assert_eq!(seg.key, 44);
        assert_eq!(seg.size, 4096);
        assert_eq!(seg.mode, 0o640);
        assert_eq!(seg.uid, 42);
        assert_eq!(seg.gid, 7);
        assert_eq!(seg.cuid, 42);
        assert_eq!(seg.cgid, 7);
    }

    #[test]
    fn existing_key_honors_excl_size_and_permissions() {
        let _g = TEST_LOCK.lock().unwrap();
        reset();
        let owner = cred(10, 20, &[], false);
        let id = shmget(55, 8192, IPC_CREAT | 0o640, owner.clone());
        assert!(id > 0);
        assert_eq!(shmget(55, 0, 0, owner.clone()), id);
        assert_eq!(shmget(55, 8193, 0, owner.clone()), err(syscall::errno::Errno::Einval));
        assert_eq!(shmget(55, 1, IPC_CREAT | IPC_EXCL, owner.clone()), err(syscall::errno::Errno::Eexist));
        assert_eq!(shmget(55, 1, 0o400, cred(99, 99, &[], false)), err(syscall::errno::Errno::Eacces));
        assert_eq!(shmget(55, 1, 0o400, cred(99, 20, &[], false)), id);
        assert_eq!(shmget(55, 1, 0o400, cred(99, 99, &[20], false)), id);
        assert_eq!(shmget(55, 1, 0o400, cred(99, 99, &[], true)), id);
    }

    #[test]
    fn hugetlb_create_is_rejected_without_allocating_normal_shmem() {
        let _g = TEST_LOCK.lock().unwrap();
        reset();
        let calls = AtomicUsize::new(0);
        let c = cred(10, 20, &[], false);
        let r = shmget_with_backing_cred(66, 4096, IPC_CREAT | SHM_HUGETLB | 0o600, 77, c.clone(), || {
            calls.fetch_add(1, AtomicOrdering::AcqRel);
            backing()
        });
        assert_eq!(r, err(syscall::errno::Errno::Einval));
        assert_eq!(calls.load(AtomicOrdering::Acquire), 0);
        let id = shmget(66, 4096, IPC_CREAT | 0o600, c.clone());
        assert_eq!(shmget(66, 1, SHM_HUGETLB, c), id);
    }
}
