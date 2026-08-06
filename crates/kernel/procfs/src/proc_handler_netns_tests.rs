use alloc::sync::Arc;
use network_namespace::NetworkNamespaceRef;

use super::{PerNetIntHook, ProcHandler};

// One `CURRENT` for four tests: the bound leaves resolve their namespace by
// CALLING `current()`, so a sibling that stores its own namespace here between
// this test's `bind()` and its `store()` redirects this test's write into the
// sibling's namespace. The fixture is a single-slot process-global, so the
// tests that drive it take this claim for their whole body. Poison is
// recovered: one failing test reports as one failure, not a cascade.
static CURRENT: std::sync::Mutex<Option<NetworkNamespaceRef>> = std::sync::Mutex::new(None);

static CURRENT_CLAIM: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn claim_current() -> std::sync::MutexGuard<'static, ()> {
    let claim = CURRENT_CLAIM.lock().unwrap_or_else(|e| e.into_inner());
    // Namespace allocation requires the production final-drop publication
    // hook. Installing it is part of this fixture's ownership contract, not a
    // side effect one test may accidentally provide for its siblings.
    net::net_ns::install_final_drop_pending_notifier()
        .expect("install final-drop pending notifier");
    claim
}

fn current() -> NetworkNamespaceRef {
    Arc::clone(CURRENT.lock().unwrap().as_ref().unwrap())
}

fn get(namespace: &NetworkNamespaceRef, key: usize) -> Result<i64, ()> {
    let key = net::net_ns::NetSysctlKey::from_usize(key).ok_or(())?;
    net::sysctl::value(namespace, key).ok_or(())
}

fn set(namespace: &NetworkNamespaceRef, key: usize, value: i64) -> Result<(), ()> {
    let key = net::net_ns::NetSysctlKey::from_usize(key).ok_or(())?;
    net::sysctl::set_value(namespace, key, value)
}

#[test]
fn opened_net_sysctls_retain_owner_after_task_namespace_switch() {
    let _current = claim_current();
    let initial_user = namespace_identity::initial(namespace_identity::NamespaceKind::User);
    let opened_in = network_namespace::allocate(initial_user.clone()).unwrap();
    let switched_to = network_namespace::allocate(initial_user).unwrap();
    net::net_ns::materialize_state(&opened_in);
    net::net_ns::materialize_state(&switched_to);
    *CURRENT.lock().unwrap() = Some(Arc::clone(&opened_in));

    let open = |key: net::net_ns::NetSysctlKey, bounds| {
        PerNetIntHook { current_ns: current, key: key.as_usize(), get, set, bounds }
            .bind().unwrap()
    };
    let somaxconn = open(net::net_ns::NetSysctlKey::Somaxconn, Some((0, i32::MAX as i64)));
    let optmem = open(net::net_ns::NetSysctlKey::OptmemMax, Some((0, i32::MAX as i64)));
    let forwarding = open(net::net_ns::NetSysctlKey::Ipv4Conf(
        net::net_ns::Ipv4ConfDev::All, net::net_ns::Ipv4ConfKey::Forwarding), Some((0, 1)));
    *CURRENT.lock().unwrap() = Some(Arc::clone(&switched_to));

    somaxconn.store(b"512\n").unwrap();
    optmem.store(b"65536\n").unwrap();
    forwarding.store(b"1\n").unwrap();
    assert_eq!(net::sysctl::value(&opened_in, net::net_ns::NetSysctlKey::Somaxconn), Some(512));
    assert_eq!(net::sysctl::value(&opened_in, net::net_ns::NetSysctlKey::OptmemMax), Some(65_536));
    assert_eq!(net::forwarding::ipv4_enabled_for(&opened_in), Some(true));
    assert_eq!(net::sysctl::value(&switched_to, net::net_ns::NetSysctlKey::Somaxconn),
        Some(net::sysctl::DEFAULT_SOMAXCONN as i64));
    assert_eq!(net::forwarding::ipv4_enabled_for(&switched_to), Some(false));
}

fn group_range(namespace: &NetworkNamespaceRef) -> Result<(u32, u32), ()> {
    net::ping::group_range_for(namespace).ok_or(())
}

fn set_group_range(namespace: &NetworkNamespaceRef, low: u32, high: u32) -> Result<(), ()> {
    net::ping::set_group_range_for(namespace, low, high)
}

fn group_leaf(namespace: &NetworkNamespaceRef) -> Arc<dyn ProcHandler> {
    *CURRENT.lock().unwrap() = Some(Arc::clone(namespace));
    super::PerNetGroupRangeHook { current_ns: current, get: group_range, set: set_group_range }
        .bind().unwrap()
}

// The window is a two-value vector leaf: it reads back tab separated, a
// one-value write keeps the live upper bound, an inverted pair disables the
// endpoint class outright, and the reserved-invalid group is refused.
#[test]
fn ping_group_range_leaf_round_trips_the_window() {
    let _current = claim_current();
    let initial_user = namespace_identity::initial(namespace_identity::NamespaceKind::User);
    let namespace = network_namespace::allocate(initial_user).unwrap();
    net::net_ns::materialize_state(&namespace);
    let leaf = group_leaf(&namespace);

    assert_eq!(leaf.format(), b"1\t0\n".to_vec());
    leaf.store(b"0 2147483647\n").unwrap();
    assert_eq!(leaf.format(), b"0\t2147483647\n".to_vec());
    assert_eq!(net::ping::group_range_for(&namespace), Some((0, 2_147_483_647)));

    leaf.store(b"100\n").unwrap();
    assert_eq!(leaf.format(), b"100\t2147483647\n".to_vec());

    leaf.store(b"200 100\n").unwrap();
    assert_eq!(leaf.format(), b"1\t0\n".to_vec());

    leaf.store(b"5 10\n").unwrap();
    assert_eq!(leaf.store(b"0 4294967295\n"), Err(()));
    assert_eq!(leaf.store(b"nonsense\n"), Err(()));
    assert_eq!(leaf.store(b"-1 5\n"), Err(()));
    assert_eq!(leaf.format(), b"5\t10\n".to_vec(), "a refused write leaves the window alone");
}

#[test]
fn ping_group_range_windows_are_private_to_their_namespace() {
    let _current = claim_current();
    let initial_user = namespace_identity::initial(namespace_identity::NamespaceKind::User);
    let first = network_namespace::allocate(initial_user.clone()).unwrap();
    let second = network_namespace::allocate(initial_user).unwrap();
    net::net_ns::materialize_state(&first);
    net::net_ns::materialize_state(&second);
    let leaf = group_leaf(&first);
    leaf.store(b"0 4000\n").unwrap();
    // The leaf keeps the namespace it was opened in even after a task switch.
    *CURRENT.lock().unwrap() = Some(Arc::clone(&second));
    leaf.store(b"0 5000\n").unwrap();
    assert_eq!(net::ping::group_range_for(&first), Some((0, 5000)));
    assert_eq!(net::ping::group_range_for(&second), Some((1, 0)));
}

#[test]
fn buffer_ceilings_are_one_global_pair_writable_only_from_the_initial_namespace() {
    let _current = claim_current();
    use super::NetGlobalIntHook;
    use vfs::VfsError;
    let initial_user = namespace_identity::initial(namespace_identity::NamespaceKind::User);
    let container = network_namespace::allocate(initial_user).unwrap();
    net::net_ns::materialize_state(&container);
    let saved = net::sysctl::rmem_max() as i64;

    let leaf = NetGlobalIntHook {
        current_ns: current,
        get: || net::sysctl::rmem_max() as i64,
        set: |value| net::sysctl::set_rmem_max(value),
        bounds: Some(net::sysctl::RMEM_MAX_BOUNDS),
    };

    *CURRENT.lock().unwrap() = Some(network_namespace::initial());
    assert_eq!(leaf.store_vfs(b"262144\n"), Ok(()));
    assert_eq!(leaf.format(), b"262144\n".to_vec());
    // Below the protocol floor is out of the write window.
    assert_eq!(leaf.store_vfs(b"1\n"), Err(VfsError::Einval));
    assert_eq!(leaf.store_vfs(b"not-a-number\n"), Err(VfsError::Einval));

    // Every namespace reads the same number, and none but the initial one
    // may change it.
    *CURRENT.lock().unwrap() = Some(Arc::clone(&container));
    assert_eq!(leaf.format(), b"262144\n".to_vec());
    assert_eq!(leaf.store_vfs(b"524288\n"), Err(VfsError::Eacces));
    assert_eq!(leaf.format(), b"262144\n".to_vec());

    *CURRENT.lock().unwrap() = Some(network_namespace::initial());
    assert_eq!(leaf.store_vfs(&alloc::format!("{saved}\n").into_bytes()), Ok(()));
}
