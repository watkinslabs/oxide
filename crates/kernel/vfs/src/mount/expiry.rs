//! Mount expiry list (`docs/16§6`, Linux `fs/namespace.c::mark_mounts_for_expiry`).
//!
//! autofs / NFS register short-lived submounts on a per-fs expire list and call
//! a periodic sweep that auto-umounts the ones that have gone idle. The sweep is
//! a TWO-pass grace (Linux `xchg(&mnt->mnt_expiry_mark, 1)`): a member that is
//! not yet expiry-marked is marked and SURVIVES this pass (so a freshly-added or
//! recently-used mount lives one more round); a member already marked AND not
//! busy is umounted now. A mount that is referenced clears its mark via
//! [`super::mntget`], resetting the grace.
//!
//! Split out of `mount.rs` to hold the line cap; parent state reached via
//! `use super::*`. The expiry mark is one bit (`MNT_EXPIRE_MARK`) of the
//! internal `mnt_flags` word, mutated with per-bit atomic xchg semantics.

use super::*;

/// Expire-list registry: list-id → member `mnt_id`s (Linux's per-fs
/// `mnt_expire` `list_head`). Each filesystem wanting expiry owns one list.
static EXPIRE_LISTS: Spinlock<BTreeMap<u64, Vec<u64>>, MountClass> = Spinlock::new(BTreeMap::new());
/// Monotonic expire-list id source; `0` is never a valid list.
static NEXT_EXPIRE_LIST: AtomicU64 = AtomicU64::new(1);

/// Allocate a fresh expire list (Linux's per-fs `mnt_expire` list head), e.g.
/// at autofs/NFS mount. # C: O(1)
pub fn expire_list_create() -> u64 {
    let id = NEXT_EXPIRE_LIST.fetch_add(1, Ordering::Relaxed);
    EXPIRE_LISTS.lock().insert(id, Vec::new());
    id
}

/// Queue `m` onto expire `list` (Linux `do_add_mount` with MNT_SHRINKABLE →
/// `list_add_tail(&mnt->mnt_expire, …)`). Idempotent; clears any pending expiry
/// mark so the mount starts with a fresh grace. # C: O(N_list)
pub fn mnt_expire_add(list: u64, m: &Arc<Mount>) {
    m.clear_internal_flag(MNT_EXPIRE_MARK);
    let mut t = EXPIRE_LISTS.lock();
    let v = t.entry(list).or_default();
    if !v.contains(&m.mnt_id) { v.push(m.mnt_id); }
}

/// Remove `m` from expire `list` (Linux `list_del_init(&mnt->mnt_expire)`),
/// e.g. when it is umounted by hand or its grace is to be revoked. # C: O(N_list)
pub fn mnt_expire_remove(list: u64, m: &Arc<Mount>) {
    if let Some(v) = EXPIRE_LISTS.lock().get_mut(&list) { v.retain(|&id| id != m.mnt_id); }
}

/// Too-busy-to-expire test (Linux `propagate_mount_busy(mnt, 1)`): a mount with
/// child mounts, an external pin (`mnt_count`), or that is LOCKED / INTERNAL is
/// never auto-expired. # C: O(1)
fn expire_busy(m: &Arc<Mount>) -> bool {
    !m.mnt_mounts.lock().is_empty()
        || m.mnt_count() > 0
        || m.is_locked()
        || m.is_internal()
}

/// One expiry sweep over `list` (Linux `mark_mounts_for_expiry`). Marks the
/// unmarked (they survive to the next sweep), reaps the still-marked-and-idle.
/// Returns the count umounted. # C: O(N_list)
pub fn mark_mounts_for_expiry(list: u64) -> usize {
    let members: Vec<u64> = match EXPIRE_LISTS.lock().get(&list) {
        Some(v) => v.clone(), None => return 0,
    };
    let mut reap: Vec<Arc<Mount>> = Vec::new();
    for id in members.iter() {
        let Some(m) = mount_by_id(*id) else { continue; };
        // xchg(&mnt_expiry_mark, 1): set the bit, observe the prior state.
        let prev = m.set_internal_flag(MNT_EXPIRE_MARK);
        let was_marked = prev & MNT_EXPIRE_MARK != 0;
        // Just marked now (first pass) OR busy ⇒ keep; already-marked + idle ⇒ reap.
        if !was_marked || expire_busy(&m) { continue; }
        reap.push(m);
    }
    let mut n = 0;
    for m in reap.iter() {
        umount_expired(m);
        if let Some(v) = EXPIRE_LISTS.lock().get_mut(&list) { v.retain(|&id| id != m.mnt_id); }
        n += 1;
    }
    n
}

/// [D26] Production expiry sweep entry point: run one [`mark_mounts_for_expiry`]
/// pass over EVERY registered expire list (Linux's periodic
/// `mark_mounts_for_expiry` housekeeping timer, plus the autofs/NFS expiry
/// ticks). The scheduler / an autofs daemon tick calls this so the two-pass
/// grace engine actually runs in production, not only from tests. Returns the
/// total mounts reaped this pass. # C: O(N_lists × N_members)
pub fn sweep_expired_mounts() -> usize {
    let lists: Vec<u64> = EXPIRE_LISTS.lock().keys().copied().collect();
    let mut n = 0;
    for l in lists { n += mark_mounts_for_expiry(l); }
    n
}

/// Object-level detach of an expired mount (Linux `umount_tree(mnt)` on the
/// expiry path), operating on the `Arc<Mount>` directly so it is ns-correct
/// regardless of the caller's current ns: unlink from parent + hash + crossing,
/// drop the `struct mountpoint` ref, remove from the arena, mark `MNT_DETACHED`,
/// then defer (external pin) or run the SB teardown exactly as [`unregister`].
/// # C: O(siblings)
fn umount_expired(m: &Arc<Mount>) {
    let ns = m.namespace_id();
    let id = m.mnt_id;
    let mp = m.mountpoint();
    let parent = m.parent_id.load(Ordering::Acquire);
    super::unlink_from_parent(m);
    if let Some(o) = m.mnt_mp.lock().take() { put_mountpoint(&o); }
    super::mounts_unpublish(id);
    if let Some(d) = mp.as_ref() {
        super::hash_remove(parent, super::dptr(d), id);
    }
    m.mark_detached();
    if m.mnt_count() == 0 { super::put_super_if_last(&m.sb); }
    mntns::bump_gen(ns);
}
