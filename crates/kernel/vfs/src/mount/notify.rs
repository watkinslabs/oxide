//! Mount-tree change notification (Linux `fsnotify_mnt_attach` /
//! `fsnotify_mnt_detach` / `fsnotify_mnt_move`).
//!
//! A mount event names a MOUNT NAMESPACE and the unique id of the mount that
//! moved; it carries no inode and no path, so it never reaches the inode
//! notification machinery. vfs owns the choke points and the settable hook;
//! the notification subsystem installs the implementation, so vfs keeps no
//! dependency on it (same shape as `set_chroot_refs_hook`).
//!
//! Which transition produces which record is decided by the namespace the
//! mount was in BEFORE against the one it is in AFTER: entering a namespace is
//! an attach, leaving one is a detach, staying in the same namespace while
//! changing position is a move — and a move is reported as one record carrying
//! BOTH bits, not as a detach/attach pair.

use sync::{MountTable as MountClass, Spinlock};

/// A mount entered a mount namespace's tree.
pub const FS_MNT_ATTACH: u32 = 0x0100_0000;
/// A mount left a mount namespace's tree.
pub const FS_MNT_DETACH: u32 = 0x0200_0000;
/// A mount changed position INSIDE its namespace: one record carrying both
/// bits, which is what distinguishes it from an unrelated detach followed by
/// an unrelated attach.
pub const FS_MNT_MOVE: u32 = FS_MNT_ATTACH | FS_MNT_DETACH;

/// Signature of the mount-notification hook: `(ns_id, mnt_id, mask)`.
pub type MntNotifyHook = fn(u64, u64, u32);

static MNT_NOTIFY_HOOK: Spinlock<Option<MntNotifyHook>, MountClass> = Spinlock::new(None);

/// Install the mount-notification hook (kernel boot / test). # C: O(1)
pub fn set_mnt_notify_hook(f: MntNotifyHook) { *MNT_NOTIFY_HOOK.lock() = Some(f); }

/// Fire one mount notification. No-op while nothing is watching mount
/// namespaces, so an unwatched system pays one uncontended lock and a null
/// test per mount-tree change.
///
/// Called with NO mount-table lock held: the hook walks the notification
/// subsystem's own structures, and the two lock sets must not interleave.
/// # C: O(1) + hook cost
pub(crate) fn fsnotify_mnt(ns_id: u64, mnt_id: u64, mask: u32) {
    let f = *MNT_NOTIFY_HOOK.lock();
    if let Some(f) = f { f(ns_id, mnt_id, mask); }
}

/// The mount became visible in `ns_id`'s tree. # C: as [`fsnotify_mnt`]
pub(crate) fn fsnotify_mnt_attach(ns_id: u64, mnt_id: u64) {
    fsnotify_mnt(ns_id, mnt_id, FS_MNT_ATTACH);
}

/// The mount left `ns_id`'s tree. # C: as [`fsnotify_mnt`]
pub(crate) fn fsnotify_mnt_detach(ns_id: u64, mnt_id: u64) {
    fsnotify_mnt(ns_id, mnt_id, FS_MNT_DETACH);
}

/// The mount changed position without leaving `ns_id`. # C: as [`fsnotify_mnt`]
pub(crate) fn fsnotify_mnt_move(ns_id: u64, mnt_id: u64) {
    fsnotify_mnt(ns_id, mnt_id, FS_MNT_MOVE);
}

/// Which record a tree transition produces, from the namespace the mount was
/// in before (`prev`) and the one it is in after (`now`). `None` on either
/// side means "not in a namespace tree".
///
/// A namespace CHANGE is deliberately not a move: the watcher of the old
/// namespace must see the mount leave and the watcher of the new one must see
/// it arrive, and neither may be told about the other's namespace. Only the
/// same-namespace case collapses into a single `FS_MNT_MOVE` record.
/// # C: O(1)
pub fn mnt_transition_mask(prev: Option<u64>, now: Option<u64>) -> Option<(u64, u32)> {
    match (prev, now) {
        (None, Some(n)) => Some((n, FS_MNT_ATTACH)),
        (Some(p), None) => Some((p, FS_MNT_DETACH)),
        (Some(p), Some(n)) if p == n => Some((n, FS_MNT_MOVE)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A move is ONE record carrying both bits — a watcher that saw a detach
    /// and an attach instead could not tell a relocation from an unmount
    /// followed by an unrelated mount at the same instant.
    /// # C: O(1)
    #[test]
    fn same_namespace_reposition_is_a_single_move_record() {
        assert_eq!(mnt_transition_mask(Some(7), Some(7)), Some((7, FS_MNT_MOVE)));
        assert_eq!(FS_MNT_MOVE, FS_MNT_ATTACH | FS_MNT_DETACH);
    }

    #[test]
    fn entering_and_leaving_a_namespace_are_reported_to_that_namespace() {
        assert_eq!(mnt_transition_mask(None, Some(3)), Some((3, FS_MNT_ATTACH)));
        assert_eq!(mnt_transition_mask(Some(3), None), Some((3, FS_MNT_DETACH)));
    }

    /// Crossing namespaces is a detach from the old and an attach to the new,
    /// issued separately — never one record, which would leak the other
    /// namespace's identity to whichever watcher received it.
    /// # C: O(1)
    #[test]
    fn a_namespace_change_is_not_a_move() {
        assert_eq!(mnt_transition_mask(Some(1), Some(2)), None);
        assert_eq!(mnt_transition_mask(None, None), None);
    }
}
