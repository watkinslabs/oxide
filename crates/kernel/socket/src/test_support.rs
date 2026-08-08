// The one owner of the process-global state this crate's hosted suite reaches.
//
// A hosted test binary is one process, and libtest runs its bodies on many
// threads at once. Two pieces of state the socket work layer consults are
// global to that process rather than private to a test:
//
// - the network security policy registered for the INITIAL network namespace,
//   which every hosted send target is built in, and
// - the AF_UNIX in-flight/garbage-collection graph, which is not keyed by
//   anything a test owns.
//
// A lock that only the tests which ASK for it take gives mutual exclusion
// between holders and no exclusion at all against a test that forgets, so the
// requirement is CHECKED at the choke point each kind of access passes through
// (`security::admit`, `receive::install_received_fds`) rather than left to
// convention. A new test that forgets fails on its first single-threaded run.

use core::cell::Cell;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Ownership of the initial namespace's network security policy. Installing or
/// counting policy is exclusive; merely sending through the namespace is shared,
/// so the sending tests still run in parallel with each other.
static POLICY: RwLock<()> = RwLock::new(());

/// Ownership of the process-global AF_UNIX in-flight/GC graph.
static SCM: RwLock<()> = RwLock::new(());

std::thread_local! {
    static POLICY_DEPTH: Cell<u32> = const { Cell::new(0) };
    static SCM_DEPTH: Cell<u32> = const { Cell::new(0) };
}

fn enter(depth: &'static std::thread::LocalKey<Cell<u32>>) {
    depth.with(|held| held.set(held.get() + 1));
}

fn leave(depth: &'static std::thread::LocalKey<Cell<u32>>) {
    depth.with(|held| held.set(held.get() - 1));
}

/// Exclusive right to install, remove, or count policy on the initial
/// namespace. # C: O(1)
pub(crate) struct PolicyControl { _lock: RwLockWriteGuard<'static, ()> }

/// Shared right to drive sends through the initial namespace with no policy
/// installed. # C: O(1)
pub(crate) struct Unpoliced { _lock: RwLockReadGuard<'static, ()> }

/// Exclusive right to build, queue, or collect AF_UNIX in-flight rights. # C: O(1)
pub(crate) struct ScmGraph { _lock: RwLockWriteGuard<'static, ()> }

/// Take exclusive ownership of the initial namespace's policy and clear it, so
/// the test starts from a registry no earlier test left behind. # C: O(1)
pub(crate) fn policy_control() -> PolicyControl {
    let lock = POLICY.write().unwrap_or_else(|poisoned| poisoned.into_inner());
    enter(&POLICY_DEPTH);
    let _ = security::network::remove_namespace(initial_namespace());
    PolicyControl { _lock: lock }
}

/// Join the sends that require no policy on the initial namespace. # C: O(1)
pub(crate) fn unpoliced() -> Unpoliced {
    let lock = POLICY.read().unwrap_or_else(|poisoned| poisoned.into_inner());
    enter(&POLICY_DEPTH);
    Unpoliced { _lock: lock }
}

/// Take exclusive ownership of the AF_UNIX in-flight graph. # C: O(1)
pub(crate) fn scm_graph() -> ScmGraph {
    let lock = SCM.write().unwrap_or_else(|poisoned| poisoned.into_inner());
    enter(&SCM_DEPTH);
    ScmGraph { _lock: lock }
}

impl Drop for PolicyControl { fn drop(&mut self) { leave(&POLICY_DEPTH); } }
impl Drop for Unpoliced { fn drop(&mut self) { leave(&POLICY_DEPTH); } }
impl Drop for ScmGraph { fn drop(&mut self) { leave(&SCM_DEPTH); } }

/// The one hosted namespace every socket send target is built in. # C: O(1)
pub(crate) fn initial_namespace() -> u64 {
    network_namespace::initial().id().as_u64()
}

/// Refuse a send that would consult policy this thread does not own. # C: O(1)
pub(crate) fn assert_policy_owned(namespace: u64) {
    if namespace != initial_namespace() { return; }
    assert!(POLICY_DEPTH.with(Cell::get) > 0,
        "a hosted send through the initial network namespace must hold \
         test_support::unpoliced() (or policy_control() to install policy): the \
         namespace's security policy and its evaluation counters are global to \
         this process and shared with every concurrently running test");
}

/// Refuse an AF_UNIX rights transfer this thread does not own. # C: O(1)
pub(crate) fn assert_scm_owned() {
    assert!(SCM_DEPTH.with(Cell::get) > 0,
        "a hosted AF_UNIX rights transfer must hold test_support::scm_graph(): \
         the in-flight and garbage-collection graph is global to this process");
}
