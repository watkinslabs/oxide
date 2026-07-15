//! Per-namespace mountinfo poll (Linux `mounts_poll`): a `/proc/.../mountinfo`
//! reader must wake (POLLPRI|POLLERR) ONLY when its OWN mount namespace's
//! change seq advances — a mount mutation confined to a foreign namespace must
//! NOT spuriously wake it. The pre-fix `mountinfo_poll_mask` compares a single
//! GLOBAL generation, so ANY namespace's change wakes EVERY reader (cross-ns
//! notify leak / spurious wakeup). `mountinfo_poll_mask_ns` reads the per-ns
//! `seq` (already maintained by `bump_gen`) and fixes this.
//!
//! Own test binary → own copy of the vfs statics; single `#[test]` fn so the
//! shared global generation is mutated single-threaded.

use core::sync::atomic::AtomicU64;
use vfs::POLL_PRI;
use vfs::mntns;

#[test]
fn per_ns_poll_does_not_leak_across_namespaces() {
    let a = mntns::initial();
    let b = mntns::allocate(a.owner_user_namespace()).unwrap();
    let ns_a = a.id();
    let ns_b = b.id();

    // Readers seed last_seen from their own ns seq (as procfs should at open).
    let seen_a = AtomicU64::new(mntns::ns_seq(ns_a));
    let seen_b = AtomicU64::new(mntns::ns_seq(ns_b));

    // Quiescent: neither reader sees a change.
    assert_eq!(mntns::mountinfo_poll_mask_ns(ns_a, &seen_a) & POLL_PRI, 0,
        "no change yet -> no POLLPRI for ns A");
    assert_eq!(mntns::mountinfo_poll_mask_ns(ns_b, &seen_b) & POLL_PRI, 0,
        "no change yet -> no POLLPRI for ns B");

    // A mount mutation occurs in ns A only.
    mntns::bump_gen(ns_a);

    // The ns-A reader wakes...
    assert_ne!(mntns::mountinfo_poll_mask_ns(ns_a, &seen_a) & POLL_PRI, 0,
        "ns A changed -> ns A reader must get POLLPRI");
    // ...and after consuming it, goes quiet again (edge-triggered).
    assert_eq!(mntns::mountinfo_poll_mask_ns(ns_a, &seen_a) & POLL_PRI, 0,
        "ns A reader already consumed the edge -> quiet");

    // THE FIX: the ns-B reader must NOT wake from ns A's change.
    assert_eq!(mntns::mountinfo_poll_mask_ns(ns_b, &seen_b) & POLL_PRI, 0,
        "ns B unchanged -> reader must NOT spuriously wake on ns A's mutation");

    // Contrast: the GLOBAL mask DOES conflate namespaces — a global-tracking
    // reader is spuriously woken by ns A's change. This is the bug the per-ns
    // mask avoids (regression anchor: keep both behaviors distinct).
    let global_seen = AtomicU64::new(mntns::mount_generation());
    mntns::bump_gen(ns_a);
    assert_ne!(mntns::mountinfo_poll_mask(&global_seen) & POLL_PRI, 0,
        "global mask wakes on ANY ns change (the conflation the fix replaces)");
    // The ns-B reader STILL stays quiet through that second global bump.
    assert_eq!(mntns::mountinfo_poll_mask_ns(ns_b, &seen_b) & POLL_PRI, 0,
        "ns B reader stays quiet across foreign mutations");

    // And a real change in ns B finally wakes the ns-B reader.
    mntns::bump_gen(ns_b);
    assert_ne!(mntns::mountinfo_poll_mask_ns(ns_b, &seen_b) & POLL_PRI, 0,
        "ns B changed -> ns B reader must get POLLPRI");
}
