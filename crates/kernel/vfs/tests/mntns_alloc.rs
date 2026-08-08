//! Mount-namespace id allocation (a monotonic atomic sequence counter):
//! `clone(CLONE_NEWNS)` /
//! `unshare(CLONE_NEWNS)` must mint a fresh id that is (a) never 0 — id 0 is the
//! init mount namespace every task starts in, so reusing it would silently fold
//! the new ns back into init — and (b) NEVER reused, even after the previous
//! holder is reaped, so a stale `task.mount_ns` / `/proc/PID/ns/mnt` cached id
//! cannot alias a freshly-minted unrelated namespace. The pre-fix tree had no
//! canonical allocator in the work-fn layer at all (the id was minted from an
//! ad-hoc `static` inside the syscall shim, a `docs/53` layering violation);
//! `mntns::allocate` is that canonical, monotonic, owner-returning source.
//!
//! Own test binary → own copy of the vfs statics; single `#[test]` fn so the
//! shared monotonic counter is observed deterministically.

use vfs::mntns;

#[test]
fn allocated_owner_ids_are_unique_nonzero_and_never_reused() {
    let user = namespace_identity::initial(namespace_identity::NamespaceKind::User);
    let init = mntns::initial();
    assert_eq!(init.ns_id(), namespace_identity::MNT_INIT_NS_ID,
        "initial mount namespace has Linux's exact global namespace ID");
    // Every allocation is nonzero (never the init ns) and strictly increasing
    // (monotonic source), and registers a fresh empty ns object eagerly.
    let mut prev = 0u64;
    let mut prev_ns_id = init.ns_id();
    let mut seen: Vec<u64> = Vec::new();
    let mut owners = Vec::new();
    for _ in 0..256 {
        let namespace = mntns::allocate(user.clone()).unwrap();
        let id = namespace.id();
        let ns_id = namespace.ns_id();
        assert_ne!(id, 0, "a fresh ns id must never be 0 (the init namespace)");
        assert!(id > prev, "allocator is strictly monotonic: {} <= {}", id, prev);
        assert!(ns_id > prev_ns_id,
            "global namespace allocator is strictly monotonic: {} <= {}",
            ns_id, prev_ns_id);
        // Eager registration (Linux allocates the `struct mnt_namespace` up
        // front): the id resolves to a real, empty namespace object.
        assert!(mntns::ns_by_id(id).is_some(), "allocate registers the live owner");
        assert_eq!(mntns::ns_nr_mounts(id), 0, "fresh ns has no committed mounts");
        assert_eq!(mntns::ns_pending_mounts(id), 0, "fresh ns has no reservation");
        assert_eq!(mntns::ns_seq(id), 0, "fresh ns change-seq starts at 0");
        seen.push(id);
        owners.push(namespace);
        prev = id;
        prev_ns_id = ns_id;
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
    let reaped_owner = mntns::allocate(user.clone()).unwrap();
    let reaped = reaped_owner.id();
    drop(reaped_owner);
    assert!(mntns::ns_by_id(reaped).is_none(), "reaped ns object is forgotten");

    let after_owner = mntns::allocate(user.clone()).unwrap();
    let after = after_owner.id();
    assert!(after > reaped, "post-reap allocation is monotonic, not recycled: {} <= {}", after, reaped);
    assert_ne!(after, reaped, "a reaped id is never handed back out");

    let empty_owner = mntns::allocate(user).unwrap();
    let empty = empty_owner.id();
    assert_eq!(mntns::ns_nr_mounts(empty), 0, "fresh owner has no mounts");
    drop(empty_owner);
    assert!(mntns::ns_by_id(empty).is_none(), "owner drop removes an empty namespace");
}
