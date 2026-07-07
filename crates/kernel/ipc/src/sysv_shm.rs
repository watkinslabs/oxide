// SysV shared memory per `24` — bare-minimum shmget/shmat/shmdt/shmctl
// implementation backed by anonymous shared VMAs. Postgres + libuv +
// some legacy IPC paths probe these; v1 returned -ENOSYS, callers
// abort. v2 phase 25 admits + delivers a working segment registry.
//
// Scope:
//   * Segment table keyed by integer key (caller-supplied or
//     IPC_PRIVATE = 0).
//   * shmget allocates a fresh kernel buffer + returns a positive
//     segment id (shmid).
//   * shmat maps the buffer into the caller's AS via VmaBacking::
//     KernelBytes (read-only) — for write-shared semantics across
//     processes the buffer must be HHDM-mapped + a shared anon VMA;
//     v1 takes a per-segment heap allocation and lets demand-fault
//     copy bytes into a fresh user page (per-process; not sharing
//     yet — see follow-up). This is enough for the "process probes
//     shmget+shmat+shmdt then exits cleanly" path that crash-on-
//     ENOSYS apps need.
//   * shmctl IPC_RMID frees the buffer.
//
// Real shared semantics (write in process A visible in process B)
// requires page-cache-level sharing of physical frames across AS
// boundaries — that's the v2 phase 28 (userfaultfd / shared-mapping)
// substrate work.

#![allow(dead_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};

use sync::{Spinlock, TaskList as ShmLockClass};

const IPC_PRIVATE: i32 = 0;

/// `shmctl` cmd values (Linux).
const IPC_RMID: u64 = 0;
const IPC_STAT: u64 = 2;
const IPC_INFO: u64 = 3;

const PAGE_SIZE: u64 = 4096;
const SHM_MIN_SIZE: usize = 1;
const SHM_MAX_SIZE: usize = 64 * 1024 * 1024; // 64 MiB v1 cap

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

struct ShmRegistry {
    next_id: AtomicI32,
    segs: Spinlock<Vec<Arc<ShmSegment>>, ShmLockClass>,
}

static REG: ShmRegistry = ShmRegistry {
    next_id: AtomicI32::new(1),
    segs: Spinlock::new(Vec::new()),
};

/// `shmget` registry entry. The syscalls shim (which can reach tmpfs) builds
/// the shared shmem `backing` and passes it here with the creator pid `cpid`.
/// Returns the existing id for a known (ns,key), else registers a new segment.
/// # C: O(N_segments) on lookup
pub fn shmget_with_backing(
    key: i32, size: usize, flg: u64, cpid: u32,
    backing: Arc<dyn vmm::FileBacking>,
) -> i64 {
    use syscall::errno::Errno;
    if size < SHM_MIN_SIZE || size > SHM_MAX_SIZE {
        return -(Errno::Einval.as_i32() as i64);
    }
    let ns = current_ipc_ns();
    if key != IPC_PRIVATE {
        // Lookup by (ns, key) — an existing segment is returned; the freshly
        // built backing is simply dropped.
        let g = REG.segs.lock();
        for s in g.iter() {
            if s.key == key && s.ns == ns {
                return s.id as i64;
            }
        }
    }
    let id = REG.next_id.fetch_add(1, Ordering::AcqRel);
    let seg = Arc::new(ShmSegment {
        id, key, ns, size,
        mode: (flg & 0o777) as u32,
        cpid,
        nattch: core::sync::atomic::AtomicI64::new(0),
        backing,
    });
    let mut g = REG.segs.lock();
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
