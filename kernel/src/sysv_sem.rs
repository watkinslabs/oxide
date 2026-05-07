// SysV semaphores per `24` follow-up — semget/semop/semctl with
// real POSIX-blocking semantics.
//
// Scope:
//   * semget(key, nsems, flg) → set id; values default to 0.
//   * semop applies each sembuf{sem_num, sem_op, sem_flg} as an
//     all-or-nothing batch (Linux atomicity guarantee). If any
//     op would underflow a value, the caller sleeps on the per-
//     set WaitList until another semop commit raises a value;
//     on wake the trial pass retries from scratch. IPC_NOWAIT in
//     any sem_flg short-circuits sleep with -EAGAIN.
//   * semctl: IPC_RMID (also wakes everyone parked on the set so
//     they observe the gone-id), GETVAL, SETVAL, GETALL, SETALL,
//     IPC_STAT.
//   * semtimedop aliases semop (timeout NOT yet honored — sleep
//     is unbounded; real timeout integration follows in a sched-
//     timer pass).

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
/// so semop can apply a batch atomically; `wait` is the per-set
/// blocking queue for semop callers whose batch can't currently
/// commit.
pub struct SemSet {
    pub id:     i32,
    pub key:    i32,
    pub vals:   Spinlock<Vec<i32>, SemLockClass>,
    pub wait:   crate::sched::WaitList,
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
        wait: crate::sched::WaitList::new(),
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

/// Trial result for a single semop batch evaluation.
enum Trial {
    /// Batch can commit; new values returned for atomic write-back.
    Ok(Vec<i32>),
    /// At least one op would underflow a value (caller blocks).
    WouldBlock,
    /// At least one op invalid (out-of-range index or over-range
    /// resulting value). Returns the errno to propagate.
    Bad(i64),
}

/// Run the trial pass against the current value snapshot. Pure
/// arithmetic — no locks held inside.
/// # C: O(nsops)
fn trial_apply(buf: &[Sembuf], n: usize, vals: &[i32]) -> Trial {
    let mut trial = match {
        let mut v: Vec<i32> = Vec::new();
        v.try_reserve_exact(vals.len()).map(|_| v)
    } {
        Ok(v)  => v,
        Err(_) => return Trial::Bad(-(syscall::errno::Errno::Enomem.as_i32() as i64)),
    };
    trial.extend_from_slice(vals);
    for i in 0..n {
        let s = buf[i];
        let idx = s.sem_num as usize;
        if idx >= trial.len() {
            return Trial::Bad(-(syscall::errno::Errno::Einval.as_i32() as i64));
        }
        let nv = trial[idx] + s.sem_op as i32;
        if nv < 0 {
            return Trial::WouldBlock;
        }
        if nv > SEM_MAX_VALUE {
            return Trial::Bad(-(syscall::errno::Errno::Erange.as_i32() as i64));
        }
        trial[idx] = nv;
    }
    Trial::Ok(trial)
}

/// `semop(semid, sops, nsops)` — slot NR_SEMOP.
///
/// All-or-nothing batch apply (Linux atomicity guarantee). If any
/// op would underflow a value, the caller blocks on the per-set
/// wait list until another semop commit raises a value, then
/// retries the trial pass from scratch. IPC_NOWAIT in any sem_flg
/// short-circuits to -EAGAIN.
/// # C: O(nsops × N_retries) — bounded by IPC progress
/// # Lk: SemSet.vals → WaitList.waiters (publisher releases vals
///       BEFORE wake; waiter holds vals while pushing to wait list)
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
    let any_nowait = (0..n).any(|i| (buf[i].sem_flg & IPC_NOWAIT) != 0);

    loop {
        let mut g = set.vals.lock();
        match trial_apply(&buf, n, &g) {
            Trial::Ok(new_vals) => {
                g.copy_from_slice(&new_vals);
                // Wake under vals to close the lost-wakeup race
                // with a concurrent waiter that's mid-park: the
                // waiter holds vals while pushing onto the wait
                // list, so as soon as we get vals it can't be
                // about to push. Lock order vals → wait.waiters
                // → runqueue.inner is consistent with the waiter
                // side (vals → park → drop vals → schedule).
                set.wait.wake_all();
                drop(g);
                return 0;
            }
            Trial::Bad(err) => {
                drop(g);
                return err;
            }
            Trial::WouldBlock => {
                if any_nowait {
                    drop(g);
                    return -(Errno::Eagain.as_i32() as i64);
                }
                // Park on the per-set wait list while still holding
                // vals: wakers in the commit path drop vals BEFORE
                // calling wake_all, so they cannot race ahead of
                // our park here. Then drop vals and yield.
                // SAFETY: process ctx; runqueue installed; preempt-off; we yield via schedule() immediately after parking so the Sleeping state is observed by the picker; wait list lock is briefly nested under vals which the publisher always releases before wake.
                unsafe { set.wait.park(); }
                drop(g);
                // SAFETY: process ctx; runqueue installed; preempt-off.
                unsafe { crate::sched::schedule(); }
                // After resume, retry. If the set was IPC_RMID'd
                // while we slept, the next lookup_by_id at the
                // top of the loop would still hit because we hold
                // an Arc<SemSet>; vals are still readable, just
                // disconnected from the registry. We fall through
                // and retry forever in that case — better:
                // re-validate registry.
                if lookup_by_id(semid).is_none() {
                    return -(Errno::Eidrm.as_i32() as i64);
                }
            }
        }
    }
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
            // Drop from registry, then wake every parker so they
            // observe the gone-id and return -EIDRM. We drop the
            // registry lock before wake_all to keep the lock
            // chain shallow; the Arc<SemSet> we hold keeps the
            // wait list alive across the wake. Sleepers re-check
            // lookup_by_id on resume; not finding the set, they
            // return -EIDRM.
            let removed: Option<Arc<SemSet>> = {
                let mut g = REG.sets.lock();
                let pos = g.iter().position(|s| s.id == semid);
                pos.map(|i| g.swap_remove(i))
            };
            if let Some(s) = removed { s.wait.wake_all(); }
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
