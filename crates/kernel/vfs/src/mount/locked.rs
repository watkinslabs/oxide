//! Locked mount flags (`docs/16§6`; mirrors `lock_mnt_tree` /
//! `can_change_locked_flags` / `__has_locked_children`).
//!
//! When a mount tree is copied into a mount namespace owned by a DIFFERENT user
//! namespace, the copier is by definition unprivileged with respect to the
//! original mounter's protections: it may see the tree, but it must not be able
//! to REMOVE a protection the parent put there. Linux freezes each protection
//! that is currently on with a sticky `MNT_LOCK_*` bit, freezes the atime policy
//! unconditionally, and stamps `MNT_LOCKED` on every non-root node so the copy
//! cannot be unmounted/moved to reveal what it hides.
//!
//! The bits are WRITE-ONCE — nothing ever clears them — which is why
//! [`can_change_locked_flags`] needs no lock (Linux says the same in its comment
//! above `can_change_locked_flags`).
//!
//! Split out of `mount.rs` to hold the line cap; parent state via `use super::*`.

use super::*;

/// The frozen-protection half of Linux `lock_mnt_tree`'s loop body, as a pure
/// function of the mount's OPTION mask: "don't allow unprivileged users to
/// change mount flags" — atime is frozen whatever it is, each of RDONLY / NODEV
/// / NOSUID / NOEXEC only when currently protective. `MNT_LOCKED` is NOT
/// included; that is the separate "don't reveal what is under a mount" stamp,
/// which depends on the node's position rather than its options. # C: O(1)
pub fn lock_bits_for(opts: u64) -> u32 {
    let mut add = MNT_LOCK_ATIME;
    if opts & MNT_RDONLY != 0 { add |= MNT_LOCK_READONLY; }
    if opts & MNT_NODEV  != 0 { add |= MNT_LOCK_NODEV; }
    if opts & MNT_NOSUID != 0 { add |= MNT_LOCK_NOSUID; }
    if opts & MNT_NOEXEC != 0 { add |= MNT_LOCK_NOEXEC; }
    add
}

/// One iteration of Linux `lock_mnt_tree`'s `for (p = mnt; p; p = next_mnt(p,
/// mnt))` body. `hide` is that loop's `p != mnt` — whether this node also gets
/// `MNT_LOCKED`, which an auto-expiring submount must not get (Linux's
/// `list_empty(&p->mnt_expire)`) or it could never be reaped. # C: O(1)
fn lock_one(m: &Arc<Mount>, hide: bool) {
    let mut add = lock_bits_for(m.flags());
    if hide && !expiry::on_any_expire_list(m.mnt_id) { add |= MNT_LOCKED; }
    m.set_internal_flag(add);
}

/// Linux `lock_mnt_tree`: freeze the protections currently in force on every
/// mount of namespace `ns`, and lock every node except the namespace root
/// against unmount/move. # C: O(N_ns_mounts)
pub(super) fn lock_mnt_ns(ns: u64) {
    let root = root_mount_id(ns);
    for m in mounts_in_ns(ns) { lock_one(&m, Some(m.mnt_id) != root); }
}

/// Linux `lock_mnt_tree(new_ns_root)`, run when a new mount namespace is
/// created — the `open_tree(OPEN_TREE_CLONE)` / `fsmount` detached-copy path. Linux
/// hangs the copy under a synthetic nullfs namespace root and locks from THAT
/// root, so the copy's own root node is `p != mnt` and does receive `MNT_LOCKED`;
/// this tree's [`DetachedMountTree`] has no synthetic root, so every node is
/// hidden. Caller decides the `user_ns != ns->user_ns` condition — the calling
/// task's user namespace is a scheduler fact, not a mount-tree one. # C: O(N)
pub fn lock_detached_tree(tree: &DetachedMountTree) {
    for node in tree.iter() { lock_one(&node.m, true); }
}

/// Linux `can_change_locked_flags`: `new_opts` (the MNT_* option word the
/// caller's remount / `mount_setattr` would install) may not drop a protection
/// this mount has frozen, nor alter a frozen atime policy. Callers turn `false`
/// into `EPERM` — Linux's errno for both `do_remount` and `do_mount_setattr`.
/// # C: O(1)
pub fn can_change_locked_flags(m: &Mount, new_opts: u64) -> bool {
    can_change_locked_options(m.flags(), m.internal_flags(), new_opts)
}

/// Pure locked-option admission used for a realized `fsmount` object whose
/// `Mount` is deliberately not materialized until `move_mount`. This is the
/// same decision as [`can_change_locked_flags`], not a second policy.
/// # C: O(1)
pub fn can_change_locked_options(old_opts: u64, fl: u32, new_opts: u64) -> bool {
    if fl & MNT_LOCK_READONLY != 0 && new_opts & MNT_RDONLY == 0 { return false; }
    if fl & MNT_LOCK_NODEV    != 0 && new_opts & MNT_NODEV  == 0 { return false; }
    if fl & MNT_LOCK_NOSUID   != 0 && new_opts & MNT_NOSUID == 0 { return false; }
    if fl & MNT_LOCK_NOEXEC   != 0 && new_opts & MNT_NOEXEC == 0 { return false; }
    if fl & MNT_LOCK_ATIME    != 0
        && (old_opts & MNT_ATIME_MASK) != (new_opts & MNT_ATIME_MASK) { return false; }
    true
}

/// Linux `__has_locked_children`: does a DIRECT child of `m` mounted at or under
/// `base` carry `MNT_LOCKED`? (Linux walks `mnt->mnt_mounts` only, not the whole
/// subtree — a locked grandchild is already covered by its own locked parent.) A
/// NON-recursive bind of such a subtree is refused with EINVAL
/// (`__do_loopback`, `open_tree(OPEN_TREE_CLONE)` without `AT_RECURSIVE`),
/// because the bind would expose the directory the locked child was covering.
/// # C: O(children)
pub fn has_locked_children(m: &Arc<Mount>, base: &Arc<Dentry>) -> bool {
    m.mnt_mounts.lock().iter().any(|c| {
        c.is_locked() && c.mountpoint().map(|mp| mp.is_subdir_of(base)).unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bit values are the REAL Linux `mount_flags` enum ones; a wrong value
    /// would silently alias another flag.
    #[test]
    fn lock_bit_values_match_linux() {
        assert_eq!(MNT_LOCK_ATIME,    0x040000);
        assert_eq!(MNT_LOCK_NOEXEC,   0x080000);
        assert_eq!(MNT_LOCK_NOSUID,   0x100000);
        assert_eq!(MNT_LOCK_NODEV,    0x200000);
        assert_eq!(MNT_LOCK_READONLY, 0x400000);
        assert_eq!(MNT_LOCKED,        0x800000);
        assert_eq!(MNT_LOCK_MASK & MNT_LOCKED, 0, "MNT_LOCKED is not a MNT_LOCK_* bit");
        assert_eq!(MNT_LOCK_MASK & MNT_INTERNAL, 0);
    }
}
