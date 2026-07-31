// fanotify PERMISSION events — the `FAN_*_PERM` gates the open/read/execve
// paths call before letting an access proceed, and the park-until-verdict wait
// that backs them.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use vfs::InodeRef;

use crate::inotify::types::{inode_key, PermEvent, FAN_ACCESS_PERM, FAN_ALLOW,
    FAN_OPEN_EXEC_PERM, FAN_OPEN_PERM, PERM_MARK_COUNT};

/// FAN_OPEN_PERM hook for the open path. # C: O(1) fast / O(groups)+park
pub fn check_open_perm(inode: &InodeRef) -> bool { check_perm(inode, FAN_OPEN_PERM) }

/// FAN_ACCESS_PERM hook for the read path. # C: O(1) fast / O(groups)+park
pub fn check_access_perm(inode: &InodeRef) -> bool { check_perm(inode, FAN_ACCESS_PERM) }

/// FAN_OPEN_EXEC_PERM hook for the execve path. # C: O(1) fast / O(groups)+park
pub fn check_open_exec_perm(inode: &InodeRef) -> bool { check_perm(inode, FAN_OPEN_EXEC_PERM) }

/// Boot fast-path gate: `true` iff any `FAN_*_PERM` mark is armed anywhere.
/// Lets the execve perm-gate skip its inode resolve entirely at boot (no perm
/// marks → byte-identical to the pre-gate path). # C: O(1)
pub fn perm_marks_present() -> bool { PERM_MARK_COUNT.load(Ordering::Acquire) != 0 }

/// Permission-event core. Returns `true` to allow, `false` to deny (caller
/// returns -EACCES). Fast-paths to allow when no FAN_*_PERM marks exist
/// anywhere (zero overhead on the open/read hot paths — never blocks boot).
/// Otherwise queues a perm event (tagged `perm_mask`) to each matching group
/// and parks until a verdict arrives.
/// # C: O(1) fast path; else O(groups) + park
fn check_perm(inode: &InodeRef, perm_mask: u32) -> bool {
    if PERM_MARK_COUNT.load(Ordering::Acquire) == 0 { return true; }
    let key = inode_key(inode);
    let fsid = inode.fsid();
    #[cfg(target_os = "oxide-kernel")]
    let pid = sched::current().map(|t| t.tgid.load(Ordering::Relaxed)).unwrap_or(0);
    #[cfg(not(target_os = "oxide-kernel"))]
    let pid = 0u32;
    let ev = Arc::new(PermEvent { obj: inode.clone(), pid, mask: perm_mask, response: core::sync::atomic::AtomicU32::new(0) });
    let mut queued = false;
    {
        let g = crate::inotify::dispatch::instances().lock();
        for w in g.iter() {
            let arc = match w.upgrade() { Some(a) => a, None => continue };
            if !arc.fanotify { continue; }
            let hit = arc.watches.lock().iter().any(|wi|
                wi.applies(key, fsid) && (wi.mask & perm_mask) != 0 && (wi.ignored & perm_mask) == 0);
            if hit { arc.perm_queue.lock().push_back(ev.clone()); arc.poll_subs.notify_mask(vfs::POLL_IN); arc.read_waiters.wake_all(); queued = true; }
        }
    }
    if !queued { return true; }
    loop {
        let r = ev.response.load(Ordering::Acquire);
        if r != 0 { return r == FAN_ALLOW; }
        #[cfg(target_os = "oxide-kernel")]
        // SAFETY: open syscall context; runqueue installed; yield until the
        // fanotify daemon writes a verdict or the group closes.
        unsafe { sched::live::tick_yield(); }
        #[cfg(not(target_os = "oxide-kernel"))]
        return true;
    }
}
