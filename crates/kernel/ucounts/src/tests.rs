// The `RLIMIT_NPROC` accounting contract, stated as tests so a later change
// re-checks it without reading anything but this file.

use std::sync::{Mutex, MutexGuard};

use crate::chain;
use crate::table;
use crate::{dec_rlimit, inc_rlimit, is_overlimit, register_namespace, value, Counter, UcountKey,
    RLIM_INFINITY};

/// The table and the link map are process-global, so the cases serialize.
static LOCK: Mutex<()> = Mutex::new(());

fn isolated() -> MutexGuard<'static, ()> {
    let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    table::clear_for_tests();
    chain::clear_for_tests();
    guard
}

const NPROC: Counter = Counter::Nproc;
/// An arbitrary non-initial user namespace id.
const CHILD_NS: u64 = 7;
/// A second one, sibling of [`CHILD_NS`].
const OTHER_NS: u64 = 9;

fn user(uid: u32) -> UcountKey { UcountKey::new(0, uid) }

#[test]
fn a_fresh_account_counts_zero_and_leaves_no_entry_behind() {
    let _g = isolated();
    assert_eq!(value(user(1000), NPROC), 0);
    assert_eq!(inc_rlimit(user(1000), NPROC, 1), 1);
    assert_eq!(dec_rlimit(user(1000), NPROC, 1), 0);
    assert_eq!(value(user(1000), NPROC), 0, "the entry is dropped at zero");
}

#[test]
fn accounts_are_independent_per_uid() {
    let _g = isolated();
    inc_rlimit(user(1000), NPROC, 3);
    inc_rlimit(user(1001), NPROC, 1);
    assert_eq!(value(user(1000), NPROC), 3);
    assert_eq!(value(user(1001), NPROC), 1);
}

#[test]
fn overlimit_fires_only_once_the_count_passes_the_limit() {
    let _g = isolated();
    inc_rlimit(user(1000), NPROC, 4);
    assert!(!is_overlimit(user(1000), NPROC, 4), "at the limit is still allowed");
    inc_rlimit(user(1000), NPROC, 1);
    assert!(is_overlimit(user(1000), NPROC, 4));
    dec_rlimit(user(1000), NPROC, 1);
    assert!(!is_overlimit(user(1000), NPROC, 4), "exiting a task re-opens the door");
}

#[test]
fn an_infinite_limit_is_never_overlimit() {
    let _g = isolated();
    inc_rlimit(user(1000), NPROC, 1_000_000);
    assert!(!is_overlimit(user(1000), NPROC, u64::MAX));
}

#[test]
fn a_nested_namespace_still_charges_its_creator() {
    // The escape this exists to close: without the upward charge,
    // unshare(CLONE_NEWUSER) would reset the count to zero and a uid could
    // fork without bound by nesting namespaces.
    let _g = isolated();
    let creator = user(1000);
    register_namespace(CHILD_NS, creator, RLIM_INFINITY);
    let inside = UcountKey::new(CHILD_NS, 0);

    inc_rlimit(inside, NPROC, 1);
    assert_eq!(value(inside, NPROC), 1);
    assert_eq!(value(creator, NPROC), 1, "the creating account is charged too");

    dec_rlimit(inside, NPROC, 1);
    assert_eq!(value(creator, NPROC), 0);
}

#[test]
fn a_nested_namespace_cannot_exceed_the_creators_own_limit() {
    let _g = isolated();
    let creator = user(1000);
    register_namespace(CHILD_NS, creator, RLIM_INFINITY);
    let inside = UcountKey::new(CHILD_NS, 0);
    // Four tasks inside; the creator's account carries all four.
    inc_rlimit(inside, NPROC, 4);
    // Inside the namespace, uid 0's own limit is generous...
    assert!(!is_overlimit(inside, NPROC, 100),
        "with no ceiling the outer level is unbounded");

    // ...but a ceiling recorded at namespace-creation time binds the outer
    // account, and the inner task's admission check sees it.
    register_namespace(OTHER_NS, creator, 3);
    let other = UcountKey::new(OTHER_NS, 0);
    assert!(is_overlimit(other, NPROC, 100),
        "the creator's 4 tasks already exceed the ceiling of 3 it was created with");
}

#[test]
fn sibling_namespaces_of_one_creator_share_the_creators_count() {
    let _g = isolated();
    let creator = user(1000);
    register_namespace(CHILD_NS, creator, RLIM_INFINITY);
    register_namespace(OTHER_NS, creator, RLIM_INFINITY);
    inc_rlimit(UcountKey::new(CHILD_NS, 0), NPROC, 2);
    inc_rlimit(UcountKey::new(OTHER_NS, 0), NPROC, 3);
    assert_eq!(value(creator, NPROC), 5);
    assert_eq!(value(UcountKey::new(CHILD_NS, 0), NPROC), 2, "each namespace keeps its own");
}

#[test]
fn a_namespace_chain_charges_every_level() {
    let _g = isolated();
    let root = user(1000);
    register_namespace(CHILD_NS, root, RLIM_INFINITY);
    register_namespace(OTHER_NS, UcountKey::new(CHILD_NS, 0), RLIM_INFINITY);
    inc_rlimit(UcountKey::new(OTHER_NS, 0), NPROC, 1);
    assert_eq!(value(UcountKey::new(OTHER_NS, 0), NPROC), 1);
    assert_eq!(value(UcountKey::new(CHILD_NS, 0), NPROC), 1);
    assert_eq!(value(root, NPROC), 1);
}

#[test]
fn forgetting_a_namespace_breaks_the_chain_without_touching_counts() {
    let _g = isolated();
    let creator = user(1000);
    register_namespace(CHILD_NS, creator, RLIM_INFINITY);
    let inside = UcountKey::new(CHILD_NS, 0);
    inc_rlimit(inside, NPROC, 1);
    crate::forget_namespace(CHILD_NS);
    assert_eq!(value(inside, NPROC), 1);
    dec_rlimit(inside, NPROC, 1);
    assert_eq!(value(creator, NPROC), 1,
        "an unlinked namespace can no longer reach its old creator");
}

#[test]
fn a_count_can_never_go_negative() {
    let _g = isolated();
    dec_rlimit(user(1000), NPROC, 5);
    assert_eq!(value(user(1000), NPROC), 0);
    assert!(!is_overlimit(user(1000), NPROC, 0),
        "a negative count must not read back as below the limit by accident");
}

#[test]
fn a_cyclic_link_terminates_instead_of_spinning() {
    let _g = isolated();
    register_namespace(CHILD_NS, UcountKey::new(OTHER_NS, 0), RLIM_INFINITY);
    register_namespace(OTHER_NS, UcountKey::new(CHILD_NS, 0), RLIM_INFINITY);
    // Bounded walk: this returns rather than hanging.
    inc_rlimit(UcountKey::new(CHILD_NS, 0), NPROC, 1);
    assert!(!is_overlimit(UcountKey::new(CHILD_NS, 0), NPROC, u64::MAX));
}

#[test]
fn the_initial_root_account_is_recognisable() {
    assert!(UcountKey::INIT_USER.is_init_user());
    assert!(!UcountKey::new(0, 1).is_init_user());
    assert!(!UcountKey::new(1, 0).is_init_user());
}
