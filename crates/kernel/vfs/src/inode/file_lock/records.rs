// Byte-range record-lock algebra (Linux `fs/locks.c` `posix_lock_inode`):
// owner identity, the conflict rule, and the split/merge an F_SETLK or
// F_UNLCK performs on an inode's `flc_posix` list. Pure data — the state that
// holds these entries lives in `context.rs`, the wait policy in
// `fs::posix_lock`.

extern crate alloc;

use alloc::vec::Vec;

/// `l_type` values (Linux `include/uapi/asm-generic/fcntl.h`).
pub const F_RDLCK: i16 = 0;
/// See [`F_RDLCK`].
pub const F_WRLCK: i16 = 1;
/// See [`F_RDLCK`].
pub const F_UNLCK: i16 = 2;

/// Linux `OFFSET_MAX` end sentinel. `l_len == 0` means "to EOF", which keeps
/// covering bytes appended after the lock was taken, so it is stored as an
/// unbounded end rather than resolved against the current size.
pub const RECORD_END_MAX: u64 = u64::MAX;

/// Record-lock owner identity (Linux `file_lock_core::flc_owner`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecordOwner {
    /// POSIX `fcntl(F_SETLK)` locks. Linux `fcntl_setlk` sets
    /// `flc_owner = current->files` (`fs/locks.c:2600` area), so every thread
    /// sharing one descriptor table is ONE owner, and `close(2)` of ANY
    /// descriptor for the file drops that owner's locks on the inode
    /// (`fs/open.c:1475` `filp_flush` → `locks_remove_posix`).
    Files(usize),
    /// Open-file-description `fcntl(F_OFD_SETLK)` locks. Linux
    /// `fcntl_setlk` sets `flc_owner = filp` for `FL_OFDLCK`, so the lock dies
    /// with the description's last reference (`fs/locks.c:2858`
    /// `locks_remove_file` → `locks_remove_posix(filp, filp)`).
    Ofd(usize),
}

impl RecordOwner {
    /// Linux `posix_locks_deadlock` (`fs/locks.c:1114`) returns false for any
    /// `FL_OFDLCK` caller: an OFD lock is not tied to a thread of execution,
    /// so the blocked-owner graph cannot describe it. # C: O(1)
    pub fn is_ofd(&self) -> bool { matches!(self, RecordOwner::Ofd(_)) }
}

/// One resolved byte-range lock. `end` is EXCLUSIVE; [`RECORD_END_MAX`] is
/// Linux's `OFFSET_MAX`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RecordLock {
    pub l_type: i16,
    pub start:  u64,
    pub end:    u64,
    pub owner:  RecordOwner,
    /// Linux `flc_pid` (`current->tgid`): reported by `F_GETLK`, never part of
    /// conflict detection — that is `flc_owner`'s job.
    pub pid:    u32,
}

/// Outcome of a non-sleeping record-lock application.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecordTry {
    /// `released` means an existing entry was removed or shrunk, so tasks
    /// parked on this inode must be woken — Linux `locks_unlink_lock_ctx`
    /// (`fs/locks.c:925`) → `locks_wake_up_blocks`.
    Acquired { released: bool },
    /// A foreign lock overlaps. `blocker` is its owner, Linux `flc_blocker`,
    /// the edge the deadlock walk follows.
    Blocked { blocker: RecordOwner },
}

/// Half-open `[a_start, a_end)` vs `[b_start, b_end)` intersection. # C: O(1)
fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

/// Overlapping OR abutting — the test Linux's `posix_lock_inode` merge pass
/// uses to keep one owner's same-type runs as a single entry. # C: O(1)
fn ranges_mergeable(a: &RecordLock, b: &RecordLock) -> bool {
    a.start <= b.end && b.start <= a.end
}

/// First foreign lock that conflicts with `req`, or `None` when `req` may be
/// applied. Linux `posix_locks_conflict`: same owner never conflicts (the
/// request replaces its own overlap), and two read locks are compatible.
/// # C: O(N_entries)
pub fn find_conflict(entries: &[RecordLock], req: &RecordLock) -> Option<RecordLock> {
    if req.l_type == F_UNLCK { return None; }
    for e in entries {
        if e.owner == req.owner { continue; }
        if !ranges_overlap(e.start, e.end, req.start, req.end) { continue; }
        if req.l_type == F_RDLCK && e.l_type == F_RDLCK { continue; }
        return Some(*e);
    }
    None
}

/// Fold the entry at the end of `out` into every same-owner same-type entry it
/// overlaps or abuts, so one owner's contiguous run stays a single record —
/// what `F_GETLK` reports and what keeps the list from growing per call.
/// # C: O(N_entries^2)
fn coalesce_last(out: &mut Vec<RecordLock>) {
    let Some(mut cur) = out.pop() else { return };
    let mut i = 0;
    while i < out.len() {
        let mergeable = out[i].owner == cur.owner && out[i].l_type == cur.l_type
            && ranges_mergeable(&out[i], &cur);
        if !mergeable { i += 1; continue; }
        let e = out.remove(i);
        if e.start < cur.start { cur.start = e.start; }
        if e.end > cur.end { cur.end = e.end; }
        i = 0;
    }
    out.push(cur);
}

/// Apply `req` to `entries` with no conflict check (the caller ran
/// [`find_conflict`] first). The caller's own overlapping entries are carved
/// out — Linux replaces a POSIX lock's overlap rather than stacking — and the
/// straddling remainders survive. `F_UNLCK` only carves. Returns `true` when
/// any existing entry was removed or shrunk, which is the caller's cue to wake
/// parked contenders. # C: O(N_entries^2)
pub fn apply(entries: &mut Vec<RecordLock>, req: &RecordLock) -> bool {
    let mut out: Vec<RecordLock> = Vec::with_capacity(entries.len() + 2);
    let mut released = false;
    for e in entries.drain(..) {
        if e.owner != req.owner || !ranges_overlap(e.start, e.end, req.start, req.end) {
            out.push(e);
            continue;
        }
        released = true;
        if e.start < req.start { out.push(RecordLock { end: req.start, ..e }); }
        if e.end > req.end { out.push(RecordLock { start: req.end, ..e }); }
    }
    if req.l_type != F_UNLCK {
        out.push(*req);
        coalesce_last(&mut out);
    }
    *entries = out;
    released
}

/// Drop every entry owned by `owner` (Linux `locks_remove_posix`, which
/// applies one `F_UNLCK` over `[0, OFFSET_MAX]` for that owner). `true` when
/// something was removed. # C: O(N_entries)
pub fn remove_owner(entries: &mut Vec<RecordLock>, owner: RecordOwner) -> bool {
    let before = entries.len();
    entries.retain(|e| e.owner != owner);
    entries.len() != before
}
