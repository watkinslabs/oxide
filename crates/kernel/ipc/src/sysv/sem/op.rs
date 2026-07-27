//! `semop(2)` / `semtimedop(2)` — Linux `do_semtimedop`, `__do_semtimedop` and
//! `perform_atomic_semop[_slow]` (`ipc/sem.c`).

use alloc::vec::Vec;
use namespace_identity::NamespaceId;
use syscall::errno::Errno;

use super::super::block::{self, Wake};
use super::super::limits::{IPC_NOWAIT, SEMAEM, SEMOPM, SEMVMX, SEM_UNDO, S_IRUGO, S_IWUGO};
use super::super::perm::{current_ipc_cred, IpcCred};
use super::super::user::{self, errno};
use super::model::{self, Sem};
use super::undo;

/// `struct sembuf` — `unsigned short sem_num; short sem_op; short sem_flg;`,
/// packed to 6 bytes on every Linux ABI this kernel targets.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Sembuf {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: i16,
}

pub const SEMBUF_BYTES: usize = 6;
/// `struct timespec` — two 64-bit signed words.
pub const TIMESPEC_BYTES: usize = 16;
const NSEC_PER_SEC: i64 = 1_000_000_000;

/// Result of one all-or-nothing batch evaluation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Semop {
    /// Every op applied; `sempid` and `semadj` are committed.
    Done,
    /// The op at this index cannot proceed; nothing was applied.
    Block(usize),
    /// Hard failure (`ERANGE`, or `EIDRM` from an invalidated undo entry).
    Fail(Errno),
}

/// Linux `perform_atomic_semop_slow`: apply the batch incrementally and roll
/// back on the first op that cannot proceed.
///
/// Linux keeps a second, two-pass variant (`perform_atomic_semop`) for batches
/// with no duplicated `sem_num`, purely to avoid writes it might have to undo.
/// That variant is WRONG for duplicates — it validates every op against the
/// unmodified value, so `[{0,-1},{0,-1}]` on `semval == 1` would pass both
/// checks and drive the value to `-1` — which is exactly why Linux routes
/// `dupsop` batches here. Running the incremental form unconditionally is
/// identical to the fast path whenever the fast path is legal, and correct
/// where it is not.
///
/// `undo_adj` is the caller's `semadj` array, present iff any op carries
/// `SEM_UNDO`; its updates roll back with the values.
///
/// Precondition: every `sem_num` is already bounded below `sems.len()` and
/// `undo_adj.len()` — `semop_in`'s `EFBIG` gate and `undo::find_alloc`'s sizing
/// establish both before this runs.
/// # C: O(nsops)
pub fn perform_atomic_semop(sems: &mut [Sem], sops: &[Sembuf], mut undo_adj: Option<&mut [i32]>,
                            pid: u32) -> Semop
{
    let mut applied = 0usize;
    let mut failure: Option<Semop> = None;
    while applied < sops.len() {
        let s = sops[applied];
        let idx = s.sem_num as usize;
        let cur = sems[idx].val;
        // (2) wait-for-zero blocks while the value is non-zero.
        if s.sem_op == 0 && cur != 0 { failure = Some(Semop::Block(applied)); break; }
        let result = cur + s.sem_op as i32;
        // (3) a decrement below zero blocks; (1) an increment never blocks.
        if result < 0 { failure = Some(Semop::Block(applied)); break; }
        if result > SEMVMX { failure = Some(Semop::Fail(Errno::Erange)); break; }
        if s.sem_flg & SEM_UNDO != 0 {
            if let Some(adj) = undo_adj.as_deref_mut() {
                let u = adj[idx] - s.sem_op as i32;
                if u < -(SEMAEM + 1) || u > SEMAEM {
                    failure = Some(Semop::Fail(Errno::Erange));
                    break;
                }
                adj[idx] = u;
            }
        }
        sems[idx].val = result;
        applied += 1;
    }
    let Some(outcome) = failure else {
        for s in sops { sems[s.sem_num as usize].pid = pid; }
        return Semop::Done;
    };
    for j in (0..applied).rev() {
        let s = sops[j];
        let idx = s.sem_num as usize;
        sems[idx].val -= s.sem_op as i32;
        if s.sem_flg & SEM_UNDO != 0 {
            if let Some(adj) = undo_adj.as_deref_mut() { adj[idx] += s.sem_op as i32; }
        }
    }
    outcome
}

/// The per-batch facts `__do_semtimedop` derives before touching the set.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BatchScan {
    /// Highest `sem_num` named, for the `EFBIG` bound.
    pub max: u16,
    /// True iff ANY op has `sem_op != 0`; selects `S_IWUGO` over `S_IRUGO`.
    pub alter: bool,
    /// True iff ANY op carries `SEM_UNDO`.
    pub undos: bool,
}

/// # C: O(nsops)
pub fn scan_batch(sops: &[Sembuf]) -> BatchScan {
    let mut out = BatchScan { max: 0, alter: false, undos: false };
    for s in sops {
        if s.sem_num >= out.max { out.max = s.sem_num; }
        if s.sem_flg & SEM_UNDO != 0 { out.undos = true; }
        if s.sem_op != 0 { out.alter = true; }
    }
    out
}

/// Linux `timespec64_valid` + `ktime_add_safe`: a `semtimedop` timeout is
/// RELATIVE, and an absolute monotonic deadline is what the park wants.
/// A `{0,0}` timeout therefore yields a deadline that has already passed, which
/// is Linux's "poll once, then `EAGAIN`".
/// # C: O(1)
pub fn deadline_from(timeout: Option<(i64, i64)>) -> Result<Option<u64>, Errno> {
    let Some((sec, nsec)) = timeout else { return Ok(None) };
    if sec < 0 || nsec < 0 || nsec >= NSEC_PER_SEC { return Err(Errno::Einval); }
    let rel = (sec as u64).saturating_mul(NSEC_PER_SEC as u64).saturating_add(nsec as u64);
    Ok(Some(block::now_ns().saturating_add(rel)))
}

/// The park API reserves `0` for "no timeout", so a deadline that legitimately
/// lands there is nudged one nanosecond forward rather than silently becoming
/// infinite. The already-expired case never reaches a park. # C: O(1)
fn park_deadline(exp: Option<u64>) -> u64 { exp.map(|d| d.max(1)).unwrap_or(0) }

/// # C: O(nsops)
pub fn read_sops(ptr: u64, nsops: usize) -> Result<Vec<Sembuf>, Errno> {
    let mut raw: Vec<u8> = Vec::new();
    if raw.try_reserve_exact(nsops * SEMBUF_BYTES).is_err() { return Err(Errno::Enomem); }
    raw.resize(nsops * SEMBUF_BYTES, 0);
    user::read_bytes(ptr, &mut raw)?;
    let mut out: Vec<Sembuf> = Vec::new();
    if out.try_reserve_exact(nsops).is_err() { return Err(Errno::Enomem); }
    for i in 0..nsops {
        let b = &raw[i * SEMBUF_BYTES..(i + 1) * SEMBUF_BYTES];
        out.push(Sembuf {
            sem_num: u16::from_le_bytes([b[0], b[1]]),
            sem_op: i16::from_le_bytes([b[2], b[3]]),
            sem_flg: i16::from_le_bytes([b[4], b[5]]),
        });
    }
    Ok(out)
}

/// # C: O(1)
pub fn read_timespec(ptr: u64) -> Result<(i64, i64), Errno> {
    let mut b = [0u8; TIMESPEC_BYTES];
    user::read_bytes(ptr, &mut b)?;
    let mut sec = [0u8; 8];
    let mut nsec = [0u8; 8];
    sec.copy_from_slice(&b[..8]);
    nsec.copy_from_slice(&b[8..]);
    Ok((i64::from_le_bytes(sec), i64::from_le_bytes(nsec)))
}

/// Body of `__do_semtimedop` with namespace, credentials and the already-copied
/// operation array supplied.
/// # C: O(nsops) per attempt, plus the sleep
/// # Lk: `SemSet::state` → `undo::UNDO`; `state` → `WaitList::waiters`
/// # Ctx: process
/// # Sleeps: yes, unless every op can commit immediately
pub fn semop_in(ns: NamespaceId, cred: &IpcCred, semid: i32, sops: &[Sembuf],
                timeout: Option<(i64, i64)>) -> Result<(), Errno>
{
    if sops.is_empty() || semid < 0 { return Err(Errno::Einval); }
    if sops.len() > SEMOPM { return Err(Errno::E2big); }
    let exp = deadline_from(timeout)?;
    let scan = scan_batch(sops);
    let tgid = block::current_tgid();

    let set = model::lookup_checked(ns, semid).ok_or(Errno::Einval)?;
    if scan.undos { undo::find_alloc(tgid, ns, semid, set.nsems)?; }
    if scan.max as usize >= set.nsems { return Err(Errno::Efbig); }
    let want = if scan.alter { S_IWUGO } else { S_IRUGO };
    if !set.perm.permitted(cred, want) { return Err(Errno::Eacces); }

    loop {
        let mut st = set.state.lock();
        if st.removed { return Err(Errno::Eidrm); }
        let outcome = if scan.undos {
            undo::with_semadj(tgid, ns, semid, |adj| match adj {
                // Linux `un->semid == -1`: an IPC_RMID invalidated this undo
                // entry while the call was in flight, and the id may now name a
                // different set entirely.
                None => Semop::Fail(Errno::Eidrm),
                Some(a) => perform_atomic_semop(&mut st.sems, sops, Some(a), tgid),
            })
        } else {
            perform_atomic_semop(&mut st.sems, sops, None, tgid)
        };
        match outcome {
            Semop::Done => {
                if scan.alter { set.commit_wake(&mut st); }
                else { st.otime = block::real_seconds(); }
                return Ok(());
            }
            Semop::Fail(e) => return Err(e),
            Semop::Block(i) => {
                let sop = sops[i];
                // Linux tests IPC_NOWAIT on the BLOCKING op only, not on the
                // batch: a NOWAIT flag riding an op that could have committed
                // does not make the call non-blocking.
                if (sop.sem_flg as i32) & IPC_NOWAIT != 0 { return Err(Errno::Eagain); }
                if let Some(d) = exp {
                    if block::now_ns() >= d { return Err(Errno::Eagain); }
                }
                st.count_blocked(sop.sem_num as usize, sop.sem_op, true);
                let dl = park_deadline(exp);
                // SAFETY: `semop_in` runs in process context on the calling task with the runqueue installed and preemption disabled; publishing happens under `state`, which every waker must also take, and the guard is dropped immediately below before the yield.
                unsafe { block::publish_park(&set.wait, dl); }
                drop(st);
                // SAFETY: this task published itself on `set.wait` just above and has since dropped `state`, holding no lock a waker needs; process context, runqueue installed, preemption disabled.
                let wake = unsafe { block::yield_and_classify(dl) };
                let mut st = set.state.lock();
                block::unpublish_park(&set.wait);
                st.count_blocked(sop.sem_num as usize, sop.sem_op, false);
                let gone = st.removed;
                drop(st);
                // A removal that raced the wake wins over the wake's own
                // reason, exactly as `freeary` stamping `queue.status` with
                // `-EIDRM` overrides a timeout in Linux.
                if gone { return Err(Errno::Eidrm); }
                match wake {
                    Wake::TimedOut => return Err(Errno::Eagain),
                    Wake::Signal => return Err(Errno::Eintr),
                    Wake::Retry => {}
                }
            }
        }
    }
}

/// Linux `do_semtimedop`: the copy-in half, whose bounds are checked BEFORE the
/// operation array is touched. # C: O(nsops)
fn do_semtimedop(semid: i32, sops_ptr: u64, nsops: usize, timeout: Option<(i64, i64)>) -> i64 {
    if nsops > SEMOPM { return errno(Errno::E2big); }
    if nsops < 1 { return errno(Errno::Einval); }
    let sops = match read_sops(sops_ptr, nsops) { Ok(v) => v, Err(e) => return errno(e) };
    let ns = match model::current_ns() { Ok(n) => n, Err(e) => return errno(e) };
    let cred = current_ipc_cred();
    match semop_in(ns, &cred, semid, &sops, timeout) { Ok(()) => 0, Err(e) => errno(e) }
}

/// `semop(semid, sops, nsops)` — slot `NR_SEMOP`. # C: O(nsops), may sleep
pub fn sys_semop(args: &syscall::SyscallArgs) -> i64 {
    do_semtimedop(args.a0 as i32, args.a1, args.a2 as u32 as usize, None)
}

/// `semtimedop(semid, sops, nsops, timeout)` — slot `NR_SEMTIMEDOP`. The
/// timeout is copied in FIRST, so a bad pointer is `EFAULT` even when `nsops`
/// is itself out of range. # C: O(nsops), may sleep
pub fn sys_semtimedop(args: &syscall::SyscallArgs) -> i64 {
    let timeout = if args.a3 == 0 { None } else {
        match read_timespec(args.a3) { Ok(t) => Some(t), Err(e) => return errno(e) }
    };
    do_semtimedop(args.a0 as i32, args.a1, args.a2 as u32 as usize, timeout)
}
