// Live BSD-process-accounting state: which file each pid namespace accounts
// to, where the next record goes, the free-space verdict that gates each
// write, and the superblock pin that lets the filesystem holding the file be
// unmounted or resealed read-only.
//
// Accounting is keyed per pid namespace, so `acct(2)` inside a container
// cannot redirect the host's accounting and vice versa, and a process exiting
// inside a container is accounted by the container AND by every ancestor
// namespace that asked.

extern crate alloc;
use alloc::collections::BTreeMap;
use sync::{Spinlock, Tty as AcctClass};
use vfs::InodeRef;

use super::parm::parms;
use super::record::AcctFacts;
use super::space::{apply_statfs, check_due, statfs_failed, SpaceCheck, SpaceState, SpaceTransition};

/// One namespace's accounting record destination: the file, and the pids the
/// record must carry as seen from THAT namespace.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NsTarget {
    pub ns_id: u64,
    /// The exiting thread group's id as seen in `ns_id`.
    pub pid:   u32,
    /// Its real parent's thread group id as seen in `ns_id`.
    pub ppid:  u32,
}

/// One namespace's accounting file.
struct AcctFile {
    inode:  InodeRef,
    /// Next append offset. Seeded from the file's size when accounting is
    /// enabled, then advanced per record — an append-mode open gets the same
    /// sequence.
    next:   u64,
    /// Free-space verdict plus when the next check falls due.
    space:  SpaceState,
}

static ACCT: Spinlock<BTreeMap<u64, AcctFile>, AcctClass> = Spinlock::new(BTreeMap::new());

/// Point `ns_id`'s accounting at `inode`, replacing any previous file. The
/// replacement is atomic from a reader's view: one namespace never accounts to
/// two files, and the pin follows the file to its new filesystem.
/// # C: O(log N_namespaces)
pub fn enable(ns_id: u64, inode: InodeRef, now_ns: u64) {
    let sb_key = inode.i_sb().map(|sb| vfs::sb_pin::sb_key(&sb)).unwrap_or(0);
    let next = inode.size();
    ACCT.lock().insert(ns_id, AcctFile { inode, next, space: SpaceState::new(now_ns) });
    // Registered AFTER the file is installed so the teardown path can never
    // observe a pin whose file is not yet there. Re-registering the same
    // cookie moves the pin off any previous filesystem.
    vfs::sb_pin::pin_insert(sb_key, ns_id, kill_for_ns);
}

/// Turn accounting off for `ns_id`. Removing an absent entry is not an error:
/// `acct(NULL)` succeeds whether or not a file was bound.
/// # C: O(log N_namespaces)
pub fn disable(ns_id: u64) {
    let had = ACCT.lock().remove(&ns_id).is_some();
    if had { vfs::sb_pin::pin_remove(ns_id); }
}

/// Superblock-pin callback: the filesystem holding `ns_id`'s accounting file is
/// being unmounted or resealed read-only, so accounting stops and the file
/// reference is dropped. Accounting stops for exactly this reason — otherwise
/// the open file would keep the filesystem from going away.
/// # C: O(log N_namespaces)
fn kill_for_ns(ns_id: u64) {
    let had = ACCT.lock().remove(&ns_id).is_some();
    if had {
        vfs::sb_pin::pin_remove(ns_id);
        klog::write_raw(b"[INFO]  acct: process accounting stopped, filesystem going away\n");
    }
}

/// Whether any namespace at all is accounting. The exit path's fast out: with
/// accounting off — the state for every boot that never calls `acct(2)` —
/// nothing beyond this load happens.
/// # C: O(1)
pub fn any_active() -> bool { !ACCT.lock().is_empty() }

/// Whether `ns_id` currently has an accounting file. # C: O(log N_namespaces)
pub fn is_enabled(ns_id: u64) -> bool { ACCT.lock().contains_key(&ns_id) }

/// Run the free-space hysteresis for `f` and answer whether this record may be
/// written. Between checks the standing verdict is reused, so a busy exit path
/// does not `statfs` per record. # C: O(1) plus one backend `statfs` when due
fn may_write(f: &mut AcctFile, now_ns: u64) -> bool {
    // A frozen filesystem is not accepting writes, and waiting for one would
    // park the exiting task behind whoever holds the freeze — which may itself
    // be waiting on this exit. Skip the record rather than risk the deadlock.
    if f.inode.i_sb().is_some_and(|sb| sb.is_frozen()) { return false; }
    match check_due(&f.space, now_ns) {
        SpaceCheck::Standing(active) => active,
        SpaceCheck::Due => {
            let Some(sb) = f.inode.i_sb() else { return statfs_failed(&f.space) };
            let Ok(st) = sb.statfs() else { return statfs_failed(&f.space) };
            let t = apply_statfs(&mut f.space, now_ns, parms(), st.f_blocks, st.f_bavail);
            match t {
                SpaceTransition::Paused =>
                    klog::write_raw(b"[INFO]  acct: process accounting paused\n"),
                SpaceTransition::Resumed =>
                    klog::write_raw(b"[INFO]  acct: process accounting resumed\n"),
                SpaceTransition::Unchanged(_) => {}
            }
            t.may_write()
        }
    }
}

/// Append one record per target that has an accounting file, carrying the pids
/// that target's namespace sees. Best-effort by construction: the task is
/// already terminating, so a write error cannot be reported to anyone and must
/// not derail the exit. The write goes straight to the inode, below the layer
/// that would charge it to the exiting task — accounting records are not
/// subject to the file-size resource limit.
/// # C: O(depth * log N_namespaces)
pub fn append(targets: &[NsTarget], facts: &AcctFacts, now_ns: u64) {
    let mut g = ACCT.lock();
    for t in targets {
        let Some(f) = g.get_mut(&t.ns_id) else { continue };
        if !may_write(f, now_ns) { continue; }
        let mut per_ns = *facts;
        per_ns.pid  = t.pid;
        per_ns.ppid = t.ppid;
        let rec = per_ns.encode();
        // Append: the record lands at the current end of file, which is the
        // larger of our own cursor and any growth another writer caused.
        let off = core::cmp::max(f.next, f.inode.size());
        match f.inode.write(off, &rec) {
            Ok(n)  => f.next = off + n as u64,
            Err(_) => { f.next = off; }
        }
    }
}
