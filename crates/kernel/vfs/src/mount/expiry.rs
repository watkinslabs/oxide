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

/// Linux `list_del_init(&mnt->mnt_expire)` where the caller does not know which
/// list holds the mount: drop `id` from EVERY expire list. `pivot_root` needs it
/// — a mount that has been relocated must not keep auto-expiring at its old
/// filesystem's request. # C: O(N_lists × N_members)
pub(super) fn mnt_expire_remove_any(id: u64) {
    for v in EXPIRE_LISTS.lock().values_mut() { v.retain(|&m| m != id); }
}

/// Linux `!list_empty(&mnt->mnt_expire)`: is this mount queued on ANY expire
/// list? `lock_mnt_tree` skips such mounts when stamping `MNT_LOCKED`, so an
/// auto-expiring (autofs/NFS) submount stays reapable inside an unprivileged
/// user-namespace copy. # C: O(N_lists × N_members)
pub(super) fn on_any_expire_list(id: u64) -> bool {
    EXPIRE_LISTS.lock().values().any(|v| v.contains(&id))
}

/// Too-busy-to-expire test: Linux `propagate_mount_busy(mnt, 1)` — which is
/// propagation-aware, so a pinned peer copy protects the mount here exactly as
/// it does at `umount(2)` — plus the two mounts an automounter must never be
/// able to reap however idle they look: one LOCKED to its parent (unmounting it
/// would reveal what its parent hid) and a kernel-INTERNAL one.
/// # C: O(N_mirrors × depth)
fn expire_busy(m: &Arc<Mount>) -> bool {
    super::busy::propagate_mount_busy(m, super::busy::PASSIVE_REFCNT)
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
    // The reap leaves every expire list as part of the shared detach path, so
    // there is no second, drift-prone list-removal here.
    for m in reap.iter() { super::detach::detach_with_propagation(m); n += 1; }
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

