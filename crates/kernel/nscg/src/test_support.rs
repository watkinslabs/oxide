// Hosted-test ownership of the process-global state nscg tests share.
//
// Two facts make an unowned nscg test schedule-dependent:
//
// 1. `network-namespace` publishes ONE immutable final-drop callback per
//    process and refuses `allocate` until it is published. A test that
//    allocated a network namespace therefore passed only when some earlier
//    test had already published it — a cross-test ordering dependency that
//    changes with the thread count. Published here from a pre-`main`
//    constructor, from exactly one call site, so no test body can observe the
//    empty slot and ordering cannot matter.
//
// 2. Enumerating the canonical active namespace registry materialises a strong
//    pin for EVERY live namespace in the process, including ones private to
//    other tests. While such a page is alive, another test's last owner drop
//    is not the final drop, so the finalizers that erase its per-namespace
//    state have not run when its `close()` returns. Enumeration and
//    finalization-observing tests are mutually exclusive; enumeration is
//    reachable only by holding `RegistryScan`, and the crate's enumeration
//    choke point (`listns::candidates`) asserts one is held.
//
// Neither guard is a second source of truth: `RwLock` membership decides who
// may touch the one registry, and the checks live at the points that touch it.

use core::cell::Cell;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use alloc::vec::Vec;
use namespace_identity::{NamespaceId, NamespacePin, NamespaceRef};

fn final_drop_notify() {}

/// Publish the hosted final-drop notifier before any test body runs. Ignoring
/// the result keeps pre-`main` code panic-free; a failed publication cannot go
/// unnoticed, because every network-namespace allocation then fails.
extern "C" fn publish_final_drop() {
    let _ = network_namespace::install_final_drop_callback(final_drop_notify);
}

#[used]
#[link_section = ".init_array"]
static PUBLISH_FINAL_DROP: extern "C" fn() = publish_final_drop;

static REGISTRY: RwLock<()> = RwLock::new(());

std::thread_local! {
    static SCANNING: Cell<usize> = const { Cell::new(0) };
    static ISOLATED: Cell<usize> = const { Cell::new(0) };
}

/// Exclusive right to enumerate the process-global active namespace registry.
pub(crate) struct RegistryScan { _guard: RwLockWriteGuard<'static, ()> }

/// Right to observe a namespace's finalizers running at its final drop, i.e.
/// the promise that no concurrent enumeration pins the dying namespace.
pub(crate) struct DropIsolation { _guard: RwLockReadGuard<'static, ()> }

/// Acquire the enumeration right. # C: O(1)
pub(crate) fn registry_scan() -> RegistryScan {
    let guard = REGISTRY.write().unwrap_or_else(|poison| poison.into_inner());
    SCANNING.with(|depth| depth.set(depth.get() + 1));
    RegistryScan { _guard: guard }
}

/// Acquire the finalization-observation right. # C: O(1)
pub(crate) fn drop_isolation() -> DropIsolation {
    let guard = REGISTRY.read().unwrap_or_else(|poison| poison.into_inner());
    ISOLATED.with(|depth| depth.set(depth.get() + 1));
    DropIsolation { _guard: guard }
}

impl Drop for RegistryScan {
    fn drop(&mut self) { SCANNING.with(|depth| depth.set(depth.get() - 1)); }
}

impl Drop for DropIsolation {
    fn drop(&mut self) { ISOLATED.with(|depth| depth.set(depth.get() - 1)); }
}

impl RegistryScan {
    /// Every active namespace in the process. # C: O(N)
    pub(crate) fn live(&self) -> Vec<NamespacePin> { namespace_identity::live_snapshot() }
}

impl DropIsolation {
    /// Whether UTS state for `id` outlived its owner. # C: O(log N)
    pub(crate) fn uts_state(&self, id: NamespaceId) -> bool { crate::uts_ns::contains(id) }

    /// Whether cgroup-root state for `id` outlived its owner. # C: O(log N)
    pub(crate) fn cgroup_state(&self, id: NamespaceId) -> bool { crate::cgroup_ns::contains(id) }
}

/// One network namespace, allocatable from any test because publication is
/// pre-`main`. # C: O(log N)
pub(crate) fn net_ns(user: NamespaceRef) -> network_namespace::NetworkNamespaceRef {
    network_namespace::allocate(user).expect("pre-main publication precedes every test")
}

/// Choke-point check for enumerating the global registry. # C: O(1)
pub(crate) fn assert_registry_scan_held() {
    assert!(SCANNING.with(Cell::get) > 0,
        "enumerating the global namespace registry pins every other test's \
         namespaces; hold `test_support::registry_scan()` across it");
}

/// Choke-point check for observing finalizer-driven state removal. # C: O(1)
pub(crate) fn assert_drop_isolation_held() {
    assert!(SCANNING.with(Cell::get) > 0 || ISOLATED.with(Cell::get) > 0,
        "a concurrent registry enumeration defers a namespace's final drop; \
         hold `test_support::drop_isolation()` across the observation");
}
