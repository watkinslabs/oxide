// Hosted coverage for `cap_capable`'s namespace walk.
//
// The rule that was missing here is the one every rootless container depends
// on: the CREATOR of a user namespace holds every capability inside it, whether
// or not it holds any outside it. Without it `has_cap_for` collapsed to "does
// the caller hold this capability at all", so an unprivileged
// `unshare(CLONE_NEWUSER|CLONE_NEWNS)` was refused CAP_SYS_ADMIN in the
// namespace it had itself just created.

use super::*;
use namespace_identity::NamespaceRef;

const CREATOR_UID: u32 = 1000;
const STRANGER_UID: u32 = 1001;

fn task(tid: u32, name: &'static str, euid: u32) -> sched::Task {
    let t = sched::Task::new(tid, name, sched::SchedClass::Normal { weight: 1024 });
    t.creds.euid.store(euid, core::sync::atomic::Ordering::Release);
    t.creds.cap_effective.store(0, core::sync::atomic::Ordering::Release);
    t
}

fn initial_user() -> NamespaceRef { namespace_identity::initial(NamespaceKind::User) }

/// A user namespace created by `euid`, as `unshare(CLONE_NEWUSER)` makes one.
fn child_of(parent: NamespaceRef, euid: u32) -> NamespaceRef {
    let ns = namespace_identity::allocate(NamespaceKind::User, parent.clone(), Some(parent))
        .unwrap();
    user_namespace::register_owner(&ns, euid).unwrap();
    ns
}

#[test]
fn the_creator_of_a_user_namespace_holds_every_capability_inside_it() {
    let t = task(700, "creator", CREATOR_UID);
    let child = child_of(initial_user(), CREATOR_UID);
    // The caller holds NOTHING in its own namespace...
    assert!(!has_cap_for(&t, &initial_user().pin(), sched::cap::SYS_ADMIN));
    // ...and everything in the one it made.
    for cap in [sched::cap::SYS_ADMIN, sched::cap::SYS_CHROOT, sched::cap::NET_ADMIN] {
        assert!(has_cap_for(&t, &child.pin(), cap),
            "the creator of a user namespace is root inside it");
    }
}

#[test]
fn a_namespace_created_by_someone_else_grants_nothing() {
    let stranger = task(701, "stranger", STRANGER_UID);
    let child = child_of(initial_user(), CREATOR_UID);
    assert!(!has_cap_for(&stranger, &child.pin(), sched::cap::SYS_ADMIN),
        "the ownership rule keys on the creating euid, not on being unprivileged");
}

/// Ownership is tested at EVERY step of the ascent, not only at the target, so
/// owning an intermediate namespace carries down to everything beneath it —
/// that is the "a capability held in a parent applies to all its children"
/// rule meeting the ownership rule. A container that creates a namespace and
/// then nests more inside it stays privileged over the whole subtree.
#[test]
fn owning_an_intermediate_namespace_carries_down_to_its_descendants() {
    let t = task(702, "creator", CREATOR_UID);
    let child = child_of(initial_user(), CREATOR_UID);
    // Created by SOMEONE ELSE, but underneath a namespace the caller owns.
    let grandchild = child_of(child.clone(), STRANGER_UID);
    assert!(has_cap_for(&t, &child.pin(), sched::cap::SYS_ADMIN));
    assert!(has_cap_for(&t, &grandchild.pin(), sched::cap::SYS_ADMIN),
        "the walk finds the owned ancestor on its way up");

    // But a stranger to the whole subtree still gets nothing.
    let stranger = task(706, "stranger", STRANGER_UID);
    assert!(!has_cap_for(&stranger, &child.pin(), sched::cap::SYS_ADMIN));
}

#[test]
fn a_capability_held_in_a_parent_applies_to_every_descendant() {
    let privileged = sched::Task::new(703, "priv", sched::SchedClass::Normal { weight: 1024 });
    let child = child_of(initial_user(), CREATOR_UID);
    let grandchild = child_of(child.clone(), CREATOR_UID);
    // Held in the initial namespace, so it applies all the way down — this is
    // the ascent terminating on rule 1 rather than on the ownership rule.
    assert!(has_cap_for(&privileged, &child.pin(), sched::cap::SYS_ADMIN));
    assert!(has_cap_for(&privileged, &grandchild.pin(), sched::cap::SYS_ADMIN));
}

#[test]
fn a_namespace_that_is_not_a_descendant_is_refused_however_privileged() {
    let t = sched::Task::new(704, "sibling", sched::SchedClass::Normal { weight: 1024 });
    let a = child_of(initial_user(), CREATOR_UID);
    let b = child_of(initial_user(), CREATOR_UID);
    // Move the caller into `a`; `b` is a sibling, reachable from neither.
    assert!(t.replace_namespace(a).is_ok());
    assert!(!has_cap_for(&t, &b.pin(), sched::cap::SYS_ADMIN),
        "the walk runs out of parents without ever meeting the caller's namespace");
}

/// A namespace whose creation was never recorded must grant nothing, or every
/// root-euid task would hold every capability in every child namespace it did
/// not create.
#[test]
fn an_unrecorded_owner_grants_nothing() {
    let t = task(705, "nocap-root", 0);
    let orphan = namespace_identity::allocate(
        NamespaceKind::User, initial_user(), Some(initial_user())).unwrap();
    assert!(!has_cap_for(&t, &orphan.pin(), sched::cap::SYS_ADMIN));
}
