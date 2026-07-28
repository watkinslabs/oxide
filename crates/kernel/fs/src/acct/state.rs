// Live BSD-process-accounting state: which file each pid namespace accounts
// to, where the next record goes, and the free-space suspend/resume hysteresis
// Linux applies before every write.
//
// Linux keys the accounting file on `pid_namespace->bacct`; this keeps the
// same shape, a map from pid-namespace id to its file, so `acct(2)` inside a
// container cannot redirect the host's accounting and vice versa.

extern crate alloc;
use alloc::collections::BTreeMap;
use sync::{Spinlock, Tty as AcctClass};
use vfs::InodeRef;

use super::record::ACCT_V3_LEN;

/// `RESUME` (`acct_parm[0]`): accounting resumes above this percentage of free
/// blocks.
pub const RESUME_PCT: u64 = 4;
/// `SUSPEND` (`acct_parm[1]`): accounting suspends below this percentage of
/// free blocks, so a full disk cannot be filled the rest of the way by the
/// accounting file itself.
pub const SUSPEND_PCT: u64 = 2;

/// One namespace's accounting file.
struct AcctFile {
    inode:  InodeRef,
    /// Next append offset. Seeded from the file's size at `acct(2)` time, then
    /// advanced per record — Linux opens with `O_APPEND` and gets the same
    /// sequence.
    next:   u64,
    /// `acct->active`: cleared by the free-space check, restored when space
    /// comes back. Linux keeps collecting records while suspended, it just
    /// does not write them.
    active: bool,
}

static ACCT: Spinlock<BTreeMap<u64, AcctFile>, AcctClass> = Spinlock::new(BTreeMap::new());

/// Point `ns_id`'s accounting at `inode`, replacing any previous file (Linux
/// `xchg(&ns->bacct, &acct->pin)` then `pin_kill(old)`).
/// # C: O(log N_namespaces)
pub fn enable(ns_id: u64, inode: InodeRef) {
    let next = inode.size();
    ACCT.lock().insert(ns_id, AcctFile { inode, next, active: true });
}

/// Turn accounting off for `ns_id` (`acct(NULL)`). Linux's `pin_kill(NULL)` on
/// a namespace that never had a file is a no-op and returns success, so
/// removing an absent entry is not an error.
/// # C: O(log N_namespaces)
pub fn disable(ns_id: u64) { ACCT.lock().remove(&ns_id); }

/// Whether any namespace at all is accounting. The exit path's fast out: with
/// accounting off — the state for every boot that never calls `acct(2)` —
/// nothing beyond this load happens.
/// # C: O(1)
pub fn any_active() -> bool { !ACCT.lock().is_empty() }

/// Linux `check_free_space`: suspend below `SUSPEND`% free blocks, resume
/// above `RESUME`%. A backend reporting no blocks at all (a pseudo filesystem,
/// `f_blocks == 0`) has no notion of fullness, so accounting stays active.
/// # C: O(1)
fn recheck_space(f: &mut AcctFile) -> bool {
    let Some(sb) = f.inode.i_sb() else { return f.active };
    let Ok(st) = sb.statfs() else { return f.active };
    if st.f_blocks == 0 { return f.active; }
    if f.active {
        if st.f_bavail <= st.f_blocks * SUSPEND_PCT / 100 {
            f.active = false;
            klog::write_raw(b"[INFO]  acct: process accounting paused\n");
        }
    } else if st.f_bavail >= st.f_blocks * RESUME_PCT / 100 {
        f.active = true;
        klog::write_raw(b"[INFO]  acct: process accounting resumed\n");
    }
    f.active
}

/// Append `rec` to the accounting file of every namespace in `chain` that has
/// one — Linux `slow_acct_process` walks `for (; ns; ns = ns->parent)` and
/// writes to each `ns->bacct` it finds, so a process exiting inside a
/// container is accounted by the container AND by every ancestor that asked.
///
/// Best-effort by construction: the task is already terminating, so a write
/// error cannot be reported to anyone and must not derail the exit.
/// # C: O(depth * log N_namespaces)
pub fn append(chain: &[u64], rec: &[u8; ACCT_V3_LEN]) {
    let mut g = ACCT.lock();
    for ns_id in chain {
        let Some(f) = g.get_mut(ns_id) else { continue };
        if !recheck_space(f) { continue; }
        // O_APPEND: the record lands at the current end of file, which is the
        // larger of our own cursor and any growth another writer caused.
        let off = core::cmp::max(f.next, f.inode.size());
        match f.inode.write(off, rec) {
            Ok(n) => f.next = off + n as u64,
            Err(_) => { f.next = off; }
        }
    }
}
