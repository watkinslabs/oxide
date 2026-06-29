//! Mount-namespace id allocation (Linux `fs/namespace.c::alloc_mnt_ns`,
//! `seq = atomic64_add_return(1, &mnt_ns_seq)`): `clone(CLONE_NEWNS)` /
//! `unshare(CLONE_NEWNS)` must mint a fresh id that is (a) never 0 — id 0 is the
//! init mount namespace every task starts in, so reusing it would silently fold
//! the new ns back into init — and (b) NEVER reused, even after the previous
//! holder is reaped, so a stale `task.mount_ns` / `/proc/PID/ns/mnt` cached id
//! cannot alias a freshly-minted unrelated namespace. The pre-fix tree had no
//! canonical allocator in the work-fn layer at all (the id was minted from an
//! ad-hoc `static` inside the syscall shim, a `docs/53` layering violation);
//! `mntns::alloc_ns_id` is that canonical, monotonic, eager-registering source.
//!
//! Own test binary → own copy of the vfs statics; single `#[test]` fn so the
//! shared monotonic counter is observed deterministically.

use vfs::mntns;

#[test]
fn alloc_ns_id_is_unique_nonzero_and_never_reused() {
    // Every allocation is nonzero (never the init ns) and strictly increasing
    // (monotonic source), and registers a fresh empty ns object eagerly.
    let mut prev = 0u64;
    let mut seen: Vec<u64> = Vec::new();
    for _ in 0..256 {
        let id = mntns::alloc_ns_id();
        assert_ne!(id, 0, "a fresh ns id must never be 0 (the init namespace)");
        assert!(id > prev, "allocator is strictly monotonic: {} <= {}", id, prev);
        // Eager registration (Linux allocates the `struct mnt_namespace` up
        // front): the id resolves to a real, empty namespace object.
        assert!(mntns::ns_by_id(id).is_some(), "alloc_ns_id registers the ns object");
        assert_eq!(mntns::ns_nr_mounts(id), 0, "fresh ns has no committed mounts");
        assert_eq!(mntns::ns_pending_mounts(id), 0, "fresh ns has no reservation");
        assert_eq!(mntns::ns_seq(id), 0, "fresh ns change-seq starts at 0");
        seen.push(id);
        prev = id;
    }
    // No collisions across the run.
    let mut sorted = seen.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), seen.len(), "every allocated id is distinct");

    // THE INVARIANT: reaping a namespace must NOT free its id for reuse. Take a
    // task into a fresh ns, then drop it to zero tasks (which reaps + forgets
    // the ns object); the next allocation must still be a brand-new id strictly
    // greater than the reaped one — never the recycled value.
    let reaped = mntns::alloc_ns_id();
    mntns::mnt_ns_enter(reaped);
    let was_reaped = mntns::mnt_ns_exit(reaped);
    assert!(was_reaped, "last task leaving the ns reaps it");
    assert!(mntns::ns_by_id(reaped).is_none(), "reaped ns object is forgotten");

    let after = mntns::alloc_ns_id();
    assert!(after > reaped, "post-reap allocation is monotonic, not recycled: {} <= {}", after, reaped);
    assert_ne!(after, reaped, "a reaped id is never handed back out");
}
