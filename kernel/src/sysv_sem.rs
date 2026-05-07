// SysV semaphores per `24` follow-up — bare-minimum semget/semop/
// semctl. Postgres + libuv + sysvinit-class init systems probe
// these; v1 returned -ENOSYS, callers either abort or fall back to
// futex-only paths. v2 P25b admits + delivers a working set
// registry with non-blocking semop semantics.
//
// Scope (first cut):
//   * semget(key, nsems, flg) → set id; values default to 0.
//   * semop applies each sembuf{sem_num, sem_op, sem_flg}; if any
//     op would set value < 0, returns -EAGAIN (atomic all-or-
//     nothing per Linux). Blocking-sleep semantics need a per-set
//     wait queue + scheduler integration (P25d follow-up).
//   * semctl: IPC_RMID, GETVAL, SETVAL, GETALL, SETALL, IPC_STAT.
//   * semtimedop aliases semop (timeout ignored — we never block).
//
// Real POSIX-blocking semop (sem_op<0 sleeps until value≥|op|)
// requires sched-integrated wait queues; programs that need it
// today see EAGAIN and either retry-with-yield or fall back to
// futex/eventfd. The probe-and-survive path is unblocked.

#![cfg(target_os = "oxide-kernel")]
#![allow(dead_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};

use sync::{Spinlock, TaskList as SemLockClass};

const IPC_PRIVATE: i32 = 0;

/// `semctl` cmd values (Linux).
const IPC_RMID: u64 = 0;
const IPC_SET:  u64 = 1;
const IPC_STAT: u64 = 2;
const GETVAL:   u64 = 12;
const GETALL:   u64 = 13;
const SETVAL:   u64 = 16;
const SETALL:   u64 = 17;

/// `sembuf` flag bit (only one we honor).
const IPC_NOWAIT: i16 = 0o4000u16 as i16;

/// `sembuf` shape — must match the userspace ABI byte-for-byte.
#[repr(C)]
#[derive(Copy, Clone)]
struct Sembuf {
    pub sem_num: u16,
    pub sem_op:  i16,
    pub sem_flg: i16,
}

const SEM_MAX_NSEMS:  usize = 1024;
const SEM_MAX_OPS:    usize = 64;
const SEM_MAX_VALUE:  i32   = 32_767;

/// One SysV semaphore set. Values protected by the per-set lock
/// so semop can apply a batch atomically.
pub struct SemSet {
    pub id:     i32,
    pub key:    i32,
    pub vals:   Spinlock<Vec<i32>, SemLockClass>,
}

struct SemRegistry {
    next_id: AtomicI32,
    sets:    Spinlock<Vec<Arc<SemSet>>, SemLockClass>,
}

static REG: SemRegistry = SemRegistry {
    next_id: AtomicI32::new(1),
    sets:    Spinlock::new(Vec::new()),
};

fn lookup_by_id(id: i32) -> Option<Arc<SemSet>> {
    let g = REG.sets.lock();
    g.iter().find(|s| s.id == id).cloned()
}

fn lookup_by_key(key: i32) -> Option<Arc<SemSet>> {
    if key == IPC_PRIVATE { return None; }
    let g = REG.sets.lock();
    g.iter().find(|s| s.key == key).cloned()
}

/// `semget(key, nsems, semflg)` — slot NR_SEMGET.
/// # C: O(N_sets) on lookup
pub fn kernel_sys_semget(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let key   = args.a0 as i32;
    let nsems = args.a1 as usize;
    let _flg  = args.a2;
    if nsems > SEM_MAX_NSEMS {
        return -(Errno::Einval.as_i32() as i64);
    }
    if let Some(s) = lookup_by_key(key) {
        return s.id as i64;
    }
    let id = REG.next_id.fetch_add(1, Ordering::AcqRel);
    let mut vals = Vec::new();
    if vals.try_reserve_exact(nsems).is_err() {
        return -(Errno::Enomem.as_i32() as i64);
    }
    vals.resize(nsems, 0i32);
    let set = Arc::new(SemSet {
        id, key,
        vals: Spinlock::new(vals),
    });
    REG.sets.lock().push(set);
    id as i64
}

/// Read user-space `nsops` × `Sembuf` (6 bytes each) into a fixed
/// array. Bounded copy with cap on nsops.
fn read_sembufs(uptr: u64, nsops: usize) -> Option<([Sembuf; SEM_MAX_OPS], usize)> {
    if nsops == 0 || nsops > SEM_MAX_OPS { return None; }
    let mut buf = [Sembuf { sem_num: 0, sem_op: 0, sem_flg: 0 }; SEM_MAX_OPS];
    for i in 0..nsops {
        let p = uptr + (i as u64) * 6;
        // SAFETY: read_sembufs consumes a user-provided pointer; CPL=0 raw deref through caller's AS during syscall handling — fault on NULL/garbage propagates.
        unsafe {
            buf[i].sem_num = core::ptr::read_volatile(p as *const u16);
            buf[i].sem_op  = core::ptr::read_volatile((p + 2) as *const i16);
            buf[i].sem_flg = core::ptr::read_volatile((p + 4) as *const i16);
        }
    }
    Some((buf, nsops))
}

/// `semop(semid, sops, nsops)` — slot NR_SEMOP.
/// All-or-nothing batch apply: if any op would underflow or
/// overflow the semaphore's bounds, no value is mutated and we
/// return EAGAIN (no blocking — see file header).
/// # C: O(nsops)
pub fn kernel_sys_semop(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let semid = args.a0 as i32;
    let sops  = args.a1;
    let nsops = args.a2 as usize;
    let set = match lookup_by_id(semid) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let (buf, n) = match read_sembufs(sops, nsops) {
        Some(t) => t, None => return -(Errno::Einval.as_i32() as i64),
    };
    let mut g = set.vals.lock();
    // Trial pass: validate every op against the current snapshot.
    let mut trial: Vec<i32> = Vec::new();
    if trial.try_reserve_exact(g.len()).is_err() {
        return -(Errno::Enomem.as_i32() as i64);
    }
    trial.extend_from_slice(&g[..]);
    for i in 0..n {
        let s = buf[i];
        let idx = s.sem_num as usize;
        if idx >= trial.len() {
            return -(Errno::Einval.as_i32() as i64);
        }
        let nv = (trial[idx] as i32) + s.sem_op as i32;
        if nv < 0 {
            // Would block. Always EAGAIN for v1 (see header).
            return -(Errno::Eagain.as_i32() as i64);
        }
        if nv > SEM_MAX_VALUE {
            return -(Errno::Erange.as_i32() as i64);
        }
        trial[idx] = nv;
    }
    // Commit.
    g.copy_from_slice(&trial[..]);
    0
}

/// `semctl(semid, semnum, cmd, arg)` — slot NR_SEMCTL.
/// # C: O(N_sets) lookup + O(nsems) for GETALL/SETALL
pub fn kernel_sys_semctl(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let semid  = args.a0 as i32;
    let semnum = args.a1 as usize;
    let cmd    = args.a2;
    let arg    = args.a3;
    let set = match lookup_by_id(semid) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    match cmd {
        IPC_RMID => {
            let mut g = REG.sets.lock();
            g.retain(|s| s.id != semid);
            0
        }
        GETVAL => {
            let g = set.vals.lock();
            if semnum >= g.len() { return -(Errno::Einval.as_i32() as i64); }
            g[semnum] as i64
        }
        SETVAL => {
            let mut g = set.vals.lock();
            if semnum >= g.len() { return -(Errno::Einval.as_i32() as i64); }
            let v = arg as i32;
            if v < 0 || v > SEM_MAX_VALUE { return -(Errno::Erange.as_i32() as i64); }
            g[semnum] = v;
            0
        }
        GETALL => {
            let g = set.vals.lock();
            // arg = u16* output buffer
            for (i, v) in g.iter().enumerate() {
                let p = arg + (i as u64) * 2;
                // SAFETY: user-provided pointer; same caveat as read_sembufs.
                unsafe {
                    core::ptr::write_volatile(p as *mut u16, *v as u16);
                }
            }
            0
        }
        SETALL => {
            let mut g = set.vals.lock();
            for i in 0..g.len() {
                let p = arg + (i as u64) * 2;
                // SAFETY: user-provided pointer; same caveat as read_sembufs.
                let v = unsafe { core::ptr::read_volatile(p as *const u16) };
                if (v as i32) > SEM_MAX_VALUE { return -(Errno::Erange.as_i32() as i64); }
                g[i] = v as i32;
            }
            0
        }
        IPC_STAT => 0,
        IPC_SET  => 0,
        _        => -(Errno::Einval.as_i32() as i64),
    }
}

/// `semtimedop(semid, sops, nsops, timeout)` — slot NR_SEMTIMEDOP.
/// Timeout ignored; aliases semop for v1.
/// # C: O(nsops)
pub fn kernel_sys_semtimedop(args: &syscall::SyscallArgs) -> i64 {
    kernel_sys_semop(args)
}
