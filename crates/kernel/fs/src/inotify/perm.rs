// fanotify PERMISSION events — the `FAN_*_PERM` gates the open/read/execve
// paths call before letting an access proceed, and the park-until-verdict wait
// that backs them.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;
use vfs::InodeRef;

use crate::inotify::fan_range;
use crate::inotify::mask::mask_applicable;
use crate::inotify::response::{validate_response, Verdict, FAN_ALLOW};
use crate::inotify::types::{inode_key, Event, InotifyData, PermState, FAN_ACCESS_PERM,
    FAN_OPEN_EXEC_PERM, FAN_OPEN_PERM, FAN_PRE_ACCESS, PERM_MARK_COUNT};

/// FAN_OPEN_PERM gate for the open path. `Ok(())` lets the open proceed.
/// # C: O(1) fast / O(groups)+park
pub fn check_open_perm(inode: &InodeRef) -> Result<(), Errno> { check_perm(inode, FAN_OPEN_PERM, None) }

/// FAN_OPEN_EXEC_PERM gate for the execve path. # C: O(1) fast / O(groups)+park
pub fn check_open_exec_perm(inode: &InodeRef) -> Result<(), Errno> {
    check_perm(inode, FAN_OPEN_EXEC_PERM, None)
}

/// THE gate every access to a file's CONTENT passes through — read, write,
/// scatter/gather and positional forms alike.
///
/// Two events, in this order and for a reason:
///   1. `FAN_PRE_ACCESS`, for reads AND writes, naming the byte range. A
///      pre-content watcher's whole job is to put the bytes there before
///      anything looks at them, so it must run first and must be told which
///      bytes.
///   2. `FAN_ACCESS_PERM`, for READS only. A content scanner inspects what is
///      there, which is only meaningful after step 1 has filled it — and a
///      write has nothing to inspect yet.
///
/// `ppos` is `None` for an access that names no range; such an event carries no
/// range record and asks about the file as a whole.
/// # C: O(1) fast path; else O(groups) + one park per group per event
pub fn check_file_area_perm(inode: &InodeRef, write: bool, ppos: Option<u64>, count: u64)
    -> Result<(), Errno> {
    if PERM_MARK_COUNT.load(Ordering::Acquire) == 0 { return Ok(()); }
    check_perm(inode, FAN_PRE_ACCESS, ppos.map(|p| fan_range::aligned_range(p, count)))?;
    if write { return Ok(()); }
    check_perm(inode, FAN_ACCESS_PERM, None)
}

/// Pre-content gate for `mmap`: the mapping is a promise that the bytes can be
/// read later, at a point where no syscall is running to be refused, so the
/// content has to be filled now. Reads and writes alike, and no
/// `FAN_ACCESS_PERM` — nothing has been inspected yet.
/// # C: O(1) fast / O(groups)+park
pub fn check_mmap_perm(inode: &InodeRef, offset: u64, len: u64) -> Result<(), Errno> {
    if PERM_MARK_COUNT.load(Ordering::Acquire) == 0 { return Ok(()); }
    check_perm(inode, FAN_PRE_ACCESS, Some(fan_range::aligned_range(offset, len)))
}

/// Pre-content gate for a size change (`truncate`/`ftruncate`). A truncate
/// destroys or extends content at a point, so the watcher is told the range
/// holding that point — the content there has to exist before it can be cut.
/// # C: O(1) fast / O(groups)+park
pub fn check_truncate_perm(inode: &InodeRef, length: u64) -> Result<(), Errno> {
    if PERM_MARK_COUNT.load(Ordering::Acquire) == 0 { return Ok(()); }
    check_perm(inode, FAN_PRE_ACCESS, Some(fan_range::aligned_range(length, 0)))
}

/// Boot fast-path gate: `true` iff any `FAN_*_PERM` mark is armed anywhere.
/// Lets the execve perm-gate skip its inode resolve entirely at boot (no perm
/// marks → byte-identical to the pre-gate path). # C: O(1)
pub fn perm_marks_present() -> bool { PERM_MARK_COUNT.load(Ordering::Acquire) != 0 }

/// The groups holding a permission mark that covers this access, in the order
/// a notification would reach them.
/// # C: O(N_groups * N_watches)
fn interested_groups(inode: &InodeRef, perm_mask: u32, is_dir: bool) -> Vec<Arc<InotifyData>> {
    let key = inode_key(inode);
    let fsid = inode.fsid();
    let mut out = Vec::new();
    let g = crate::inotify::dispatch::instances().lock();
    for w in g.iter() {
        let Some(arc) = w.upgrade() else { continue };
        if !arc.fanotify { continue; }
        let hit = arc.watches.lock().iter().any(|wi| {
            if !wi.applies(key, fsid) { return false; }
            if (wi.mask & perm_mask) == 0 { return false; }
            if !mask_applicable(wi.mask, is_dir, wi.iter_type()) { return false; }
            (wi.effective_ignore(is_dir, wi.iter_type()) & perm_mask) == 0
        });
        if hit { out.push(arc); }
    }
    out
}

/// Permission-event core. Fast-paths to allow when no `FAN_*_PERM` mark exists
/// anywhere, so the open/read hot paths pay nothing on a system without a
/// permission daemon and can never block during boot.
///
/// Otherwise each interested group is consulted IN TURN — the access is queued
/// to one group and the accessor parks until that group answers, and only then
/// is the next group asked. A denial stops the walk immediately: the access is
/// already refused, so there is nothing left for a later group to decide.
/// # C: O(1) fast path; else O(groups) + one park per group
fn check_perm(inode: &InodeRef, perm_mask: u32, range: Option<(u64, u64)>) -> Result<(), Errno> {
    if PERM_MARK_COUNT.load(Ordering::Acquire) == 0 { return Ok(()); }
    let is_dir = inode.file_type() == vfs::FileType::Directory;
    let groups = interested_groups(inode, perm_mask, is_dir);
    if groups.is_empty() { return Ok(()); }
    for group in groups {
        ask_group(&group, inode, perm_mask, range)?;
    }
    Ok(())
}

/// Queue one permission event to `group` and park until it is answered.
/// # C: O(1) + one park
fn ask_group(group: &Arc<InotifyData>, inode: &InodeRef, perm_mask: u32,
             range: Option<(u64, u64)>) -> Result<(), Errno> {
    let st = Arc::new(PermState::new());
    let ev = Event {
        wd: -1,
        mask: perm_mask,
        cookie: 0,
        name: Vec::new(),
        obj: Some(inode.clone()),
        pid: reporting_pid(group),
        perm: Some(st.clone()),
        range,
        ..Default::default()
    };
    // A closed or overflowed group never answers, so an event it refused to
    // queue must not be waited on.
    let Some(st) = group.queue_perm_event(ev) else { return Ok(()) };
    wait_for_verdict(group, &st)
}

/// The id reported for the acting process. `FAN_REPORT_TID` selects the
/// THREAD's id; otherwise it is the thread group's, which is what a daemon
/// matching against `/proc/<pid>` expects. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn reporting_pid(group: &InotifyData) -> u32 {
    let Some(t) = sched::current() else { return 0 };
    if !group.reports_tid() { return t.visible_pid(); }
    let v = t.vtid.load(Ordering::Acquire);
    if v != 0 { v } else { t.tid }
}

/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) fn reporting_pid(_group: &InotifyData) -> u32 { 0 }

/// Park until the group publishes a verdict, then report it.
///
/// The wait is KILLABLE, not fully interruptible: an ordinary signal must not
/// resume an access the daemon has not ruled on (the daemon may be about to
/// deny it), but a task being killed cannot be left parked on a daemon that
/// may never answer. On abandonment the event is marked cancelled so a verdict
/// arriving afterwards is discarded rather than applied to a dead accessor.
/// # C: O(1) + one park per wake
#[cfg(target_os = "oxide-kernel")]
fn wait_for_verdict(group: &Arc<InotifyData>, st: &Arc<PermState>) -> Result<(), Errno> {
    loop {
        if let Some(v) = verdict_of(group, st) { return v.as_result(); }
        if fatal_signal_pending() { st.cancel(); return Err(Errno::Eintr); }
        // SAFETY: syscall context on the accessing task, no VFS locks held; the
        // re-check below cancels the park if the verdict landed while
        // publishing, which is the same lost-wakeup gap the read path closes.
        unsafe { group.access_waiters.park_interruptible_with_deadline(0); }
        if st.answered().is_some() || fatal_signal_pending() {
            group.access_waiters.cancel_current_park();
            continue;
        }
        // SAFETY: this task published Sleeping through the wait list and holds no locks.
        unsafe { sched::live::schedule::schedule(); }
        group.access_waiters.remove_current();
    }
}

/// Hosted builds install no scheduler; a permission event that cannot be
/// waited on allows the access rather than spinning. # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
fn wait_for_verdict(group: &Arc<InotifyData>, st: &Arc<PermState>) -> Result<(), Errno> {
    match verdict_of(group, st) { Some(v) => v.as_result(), None => Ok(()) }
}

/// The published verdict, re-validated against the group that published it.
/// # C: O(1)
fn verdict_of(group: &InotifyData, st: &PermState) -> Option<Verdict> {
    let r = st.answered()?;
    Some(validate_response(r, group.is_pre_content(), group.audit_enabled())
        .unwrap_or(Verdict { access: FAN_ALLOW, errno: 0 }))
}

/// `fatal_signal_pending(current)` — only an unblockable kill breaks the wait.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
fn fatal_signal_pending() -> bool {
    let bit = sched::live::sigpend::Signum::Sigkill.bit();
    sched::live::deliverable_signals_self() & bit != 0
}
