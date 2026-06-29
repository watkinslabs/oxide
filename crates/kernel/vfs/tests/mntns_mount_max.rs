//! Per-namespace mount cap (Linux `sysctl_mount_max` + `count_mounts`): a
//! single `mount(2)` whose MS_SHARED propagation / rbind fan-out would push a
//! namespace past `sysctl_mount_max` must fail with ENOSPC and leave NO partial
//! reservation behind — unbounded fan-out is the DoS Linux closed with
//! `count_mounts` (commit d29216842a85). The accounting is a reserve
//! (`count_mounts`) → commit (`commit_mounts`) / abort (`abort_mounts`) /
//! detach (`dec_mounts`) cycle on `mnt_ns->{nr_mounts,pending_mounts}`.
//!
//! Own test binary → own copy of the vfs statics; single-threaded so the shared
//! `SYSCTL_MOUNT_MAX` / per-ns counters are mutated deterministically.

use vfs::VfsError;
use vfs::mntns;

// Unique ns ids well clear of anything a sibling op might create.
const NS: u64 = 0x4D4D_0001;

#[test]
fn count_commit_abort_detach_cycle() {
    // Shrink the global ceiling so the test needn't graft 100k mounts.
    mntns::set_sysctl_mount_max(10);
    mntns::ns_get_or_create(NS);
    assert_eq!(mntns::ns_nr_mounts(NS), 0, "fresh ns has no mounts");
    assert_eq!(mntns::ns_pending_mounts(NS), 0, "fresh ns has no reservation");

    // Admit 4 → reserved in pending, NOT yet live.
    mntns::count_mounts(NS, 4).expect("4 fits under cap 10");
    assert_eq!(mntns::ns_pending_mounts(NS), 4, "count_mounts reserves in pending");
    assert_eq!(mntns::ns_nr_mounts(NS), 0, "reservation is not yet live");

    // Commit the graft → reservation rolls into live nr_mounts.
    mntns::commit_mounts(NS, 4);
    assert_eq!(mntns::ns_pending_mounts(NS), 0, "commit drains the reservation");
    assert_eq!(mntns::ns_nr_mounts(NS), 4, "commit makes the 4 mounts live");

    // Admit 6 more (live 4 + 6 == cap 10) → exactly fits.
    mntns::count_mounts(NS, 6).expect("4 live + 6 == cap 10 fits exactly");
    // One more mount now would exceed the cap → ENOSPC, with the in-flight 6
    // still reserved and untouched (the over-cap probe must not consume slots).
    let over = mntns::count_mounts(NS, 1);
    assert_eq!(over, Err(VfsError::Enospc), "10 live+pending + 1 exceeds cap → ENOSPC");
    assert_eq!(mntns::ns_pending_mounts(NS), 6, "a rejected admit reserves nothing");

    // The 6-mount graft fails downstream → abort returns the reservation.
    mntns::abort_mounts(NS, 6);
    assert_eq!(mntns::ns_pending_mounts(NS), 0, "abort releases the reservation");
    assert_eq!(mntns::ns_nr_mounts(NS), 4, "abort leaves live count unchanged");

    // After the abort there's headroom again: 6 fits (4 live + 6 == 10).
    mntns::count_mounts(NS, 6).expect("post-abort headroom restored");
    mntns::commit_mounts(NS, 6);
    assert_eq!(mntns::ns_nr_mounts(NS), 10, "ns now at the ceiling");

    // At the ceiling even a single-mount graft is refused.
    assert_eq!(mntns::count_mounts(NS, 1), Err(VfsError::Enospc), "full ns refuses 1 more");

    // umount/detach decrements live; freed slots are immediately re-grantable.
    mntns::dec_mounts(NS, 3);
    assert_eq!(mntns::ns_nr_mounts(NS), 7, "detach drops 3 live mounts");
    mntns::count_mounts(NS, 3).expect("freed slots are re-grantable");
    mntns::abort_mounts(NS, 3);

    // num == 0 is a no-op admit (Linux admits an empty subtree).
    mntns::count_mounts(NS, 0).expect("empty subtree always admits");
    assert_eq!(mntns::ns_pending_mounts(NS), 0, "zero-admit reserves nothing");

    // dec_mounts saturates at 0 — a double-detach cannot underflow the count.
    mntns::dec_mounts(NS, 1000);
    assert_eq!(mntns::ns_nr_mounts(NS), 0, "over-detach saturates at zero, no wrap");

    // Restore the default ceiling so a sibling test binary isn't affected via a
    // shared process image (defensive; each test binary has its own statics).
    mntns::set_sysctl_mount_max(mntns::DEFAULT_MOUNT_MAX);
}
