//! `propagate_mount_busy` — the PROPAGATION-AWARE busy
//! test `umount(2)` and the expiry sweep both apply before detaching anything.
//!
//! Busy-ness is not a property of the named mount alone. Unmounting a mount
//! whose parent is SHARED necessarily unmounts the mirror copy under every peer
//! and slave of that parent, so a mirror that is itself pinned — or that has a
//! submount of its own — makes the WHOLE operation `EBUSY`, even when the mount
//! the caller named is perfectly idle. Only the local half of that test existed:
//! `umount2(2)` accepted a request that would have silently yanked a busy peer
//! copy out from under its users.
//!
//! One exception upstream carves out: a mirror covered COMPLETELY by a single
//! overmount is not held down by it, because pulling the mirror out leaves the
//! overmount exactly where it was. Any other child does hold it.
//!
//! The decision is a `#[cfg]`-free pure function over sampled facts so the
//! whole rule — including that exception — is a hosted unit test rather than
//! something only a boot can exercise. The sampler walks the real mount tree.

use super::*;

/// Reference base for the mount `umount2(2)` itself named: the parent mount's
/// reference plus the one this very syscall holds (Linux `propagate_mount_busy(
/// mnt, 2)` from `do_umount`).
pub const UMOUNT_SYSCALL_REFCNT: i32 = 2;
/// Reference base for a mount nobody named — the expiry sweep's candidate, and
/// every propagation mirror: its parent's reference alone (Linux
/// `propagate_mount_busy(mnt, 1)` / `do_refcount_check(child, 1)`).
pub const PASSIVE_REFCNT: i32 = 1;

/// The named mount's own facts.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BusyFacts {
    /// `!list_empty(&mnt->mnt_mounts)` — anything mounted under it.
    pub has_children: bool,
    /// `mnt_get_count(mnt)`, in Linux's counting space (the tree's own
    /// references included, not just the pins beyond them).
    pub ref_count: i32,
}

/// One propagation mirror's facts.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MirrorBusyFacts {
    /// Number of mounts attached under the mirror.
    pub child_count: usize,
    /// The mirror's ONLY child is mounted on the mirror's own root dentry, i.e.
    /// it covers the mirror completely (Linux `child->overmount`).
    pub only_child_overmounts: bool,
    /// `mnt_get_count(child)`, in Linux's counting space.
    pub ref_count: i32,
}

/// Linux `propagate_mount_busy`'s verdict: `true` ⇒ the unmount must be refused
/// with `EBUSY`.
///
/// The named mount is busy if it has ANY child or more references than the
/// caller's base. Otherwise each mirror is consulted: a mirror carrying
/// submounts of its own is skipped UNLESS its single child completely
/// overmounts it, and a mirror that survives that filter is busy on the same
/// reference test with a base of one. # C: O(N_mirrors)
pub fn propagate_busy_decision(refcnt: i32, m: &BusyFacts, mirrors: &[MirrorBusyFacts]) -> bool {
    if m.has_children || m.ref_count > refcnt { return true; }
    for mir in mirrors.iter() {
        // A mount that covers the mirror completely would not prevent it being
        // pulled out; any other child would, so the mirror is left alone.
        if mir.child_count > 0 && !(mir.child_count == 1 && mir.only_child_overmounts) { continue; }
        if mir.ref_count > PASSIVE_REFCNT { return true; }
    }
    false
}

/// Sample [`BusyFacts`] for `m` against reference base `refcnt`.
///
/// Oxide's `mnt_count` counts only the pins held BEYOND the references the tree
/// itself owns, so an idle mount reads `0` where Linux reads `refcnt`. Shift it
/// into Linux's space here rather than rewriting the rule's constants.
/// # C: O(1)
fn busy_facts(m: &Arc<Mount>, refcnt: i32) -> BusyFacts {
    BusyFacts { has_children: m.has_child_mounts(), ref_count: refcnt + m.mnt_count().max(0) }
}

/// Sample [`MirrorBusyFacts`] for one propagation mirror. # C: O(children)
fn mirror_busy_facts(mirror: &Arc<Mount>) -> MirrorBusyFacts {
    let children: Vec<Arc<Mount>> = mirror.mnt_mounts.lock().iter().cloned().collect();
    let root = mirror.mnt_root();
    let only_child_overmounts = match (children.first(), root.as_ref()) {
        (Some(c), Some(r)) if children.len() == 1 => {
            c.mountpoint().map(|mp| Arc::ptr_eq(&mp, r)).unwrap_or(false)
        }
        _ => false,
    };
    MirrorBusyFacts {
        child_count: children.len(),
        only_child_overmounts,
        ref_count: PASSIVE_REFCNT + mirror.mnt_count().max(0),
    }
}

/// Linux `propagate_mount_busy(mnt, refcnt)` over the real mount tree: sample
/// the named mount and every propagation mirror of it, then apply
/// [`propagate_busy_decision`]. `refcnt` is [`UMOUNT_SYSCALL_REFCNT`] for the
/// mount `umount2(2)` named and [`PASSIVE_REFCNT`] for one the kernel picked
/// itself. # C: O(N_mirrors × depth)
pub fn propagate_mount_busy(m: &Arc<Mount>, refcnt: i32) -> bool {
    let local = busy_facts(m, refcnt);
    // The local half alone decides for a namespace root (no parent to propagate
    // through) and short-circuits before the mirror walk, exactly as upstream.
    if local.has_children || local.ref_count > refcnt { return true; }
    if m.is_root() { return false; }
    let mirrors: Vec<MirrorBusyFacts> =
        super::propagation::peer_mirrors(m).iter().map(mirror_busy_facts).collect();
    propagate_busy_decision(refcnt, &local, &mirrors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idle() -> BusyFacts { BusyFacts { has_children: false, ref_count: UMOUNT_SYSCALL_REFCNT } }
    fn idle_mirror() -> MirrorBusyFacts {
        MirrorBusyFacts { child_count: 0, only_child_overmounts: false, ref_count: PASSIVE_REFCNT }
    }

    #[test]
    fn an_idle_mount_with_no_mirrors_is_not_busy() {
        assert!(!propagate_busy_decision(UMOUNT_SYSCALL_REFCNT, &idle(), &[]));
    }

    #[test]
    fn a_child_mount_makes_the_named_mount_busy() {
        let f = BusyFacts { has_children: true, ..idle() };
        assert!(propagate_busy_decision(UMOUNT_SYSCALL_REFCNT, &f, &[]));
    }

    #[test]
    fn a_pin_beyond_the_callers_base_makes_the_named_mount_busy() {
        let f = BusyFacts { ref_count: UMOUNT_SYSCALL_REFCNT + 1, ..idle() };
        assert!(propagate_busy_decision(UMOUNT_SYSCALL_REFCNT, &f, &[]));
        // Exactly the base is the idle reading, not a pin.
        assert!(!propagate_busy_decision(UMOUNT_SYSCALL_REFCNT, &idle(), &[]));
    }

    #[test]
    fn the_base_moves_with_the_caller() {
        // The same two references are BUSY for a sweep that named nothing and
        // IDLE for the syscall that holds one of them itself.
        let f = BusyFacts { ref_count: 2, has_children: false };
        assert!(propagate_busy_decision(PASSIVE_REFCNT, &f, &[]));
        assert!(!propagate_busy_decision(UMOUNT_SYSCALL_REFCNT, &f, &[]));
    }

    #[test]
    fn a_pinned_peer_mirror_makes_an_idle_mount_busy() {
        // The whole point of the propagation half: nothing about the mount the
        // caller named is busy, but unmounting it would yank a pinned copy.
        let mirror = MirrorBusyFacts { ref_count: PASSIVE_REFCNT + 1, ..idle_mirror() };
        assert!(propagate_busy_decision(UMOUNT_SYSCALL_REFCNT, &idle(), &[mirror]));
    }

    #[test]
    fn an_idle_peer_mirror_does_not_make_the_mount_busy() {
        assert!(!propagate_busy_decision(UMOUNT_SYSCALL_REFCNT, &idle(), &[idle_mirror()]));
    }

    #[test]
    fn a_mirror_carrying_submounts_is_skipped_not_counted() {
        // A mirror with children of its own is left where it is — it is not the
        // copy this unmount would pull out, so even a pin on it is irrelevant.
        let mirror = MirrorBusyFacts {
            child_count: 2, only_child_overmounts: false, ref_count: PASSIVE_REFCNT + 5,
        };
        assert!(!propagate_busy_decision(UMOUNT_SYSCALL_REFCNT, &idle(), &[mirror]));
    }

    #[test]
    fn a_mirror_covered_completely_by_one_overmount_is_still_consulted() {
        // Pulling the mirror out from under a mount that covers it entirely
        // leaves that mount exactly where it was, so the mirror is NOT excused
        // from the reference test the way a partially-covered one is.
        let busy = MirrorBusyFacts {
            child_count: 1, only_child_overmounts: true, ref_count: PASSIVE_REFCNT + 1,
        };
        assert!(propagate_busy_decision(UMOUNT_SYSCALL_REFCNT, &idle(), &[busy]));
        let idle_but_covered = MirrorBusyFacts {
            child_count: 1, only_child_overmounts: true, ref_count: PASSIVE_REFCNT,
        };
        assert!(!propagate_busy_decision(UMOUNT_SYSCALL_REFCNT, &idle(), &[idle_but_covered]));
    }

    #[test]
    fn a_single_child_that_does_not_cover_the_mirror_skips_it() {
        let mirror = MirrorBusyFacts {
            child_count: 1, only_child_overmounts: false, ref_count: PASSIVE_REFCNT + 1,
        };
        assert!(!propagate_busy_decision(UMOUNT_SYSCALL_REFCNT, &idle(), &[mirror]));
    }

    #[test]
    fn one_busy_mirror_among_many_is_enough() {
        let mirrors = [
            idle_mirror(),
            MirrorBusyFacts { child_count: 3, ..idle_mirror() },
            MirrorBusyFacts { ref_count: PASSIVE_REFCNT + 1, ..idle_mirror() },
        ];
        assert!(propagate_busy_decision(UMOUNT_SYSCALL_REFCNT, &idle(), &mirrors));
    }

    #[test]
    fn the_local_half_outranks_the_mirror_walk() {
        // A locally-busy mount is busy whatever the mirrors say, and an idle
        // mount with only skipped mirrors is not.
        let f = BusyFacts { has_children: true, ..idle() };
        assert!(propagate_busy_decision(UMOUNT_SYSCALL_REFCNT, &f, &[idle_mirror()]));
    }
}
