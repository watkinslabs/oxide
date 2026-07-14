use alloc::sync::Arc;
use network_namespace::NetworkNamespaceRef;

use super::{PerNetIntHook, ProcHandler};

static CURRENT: std::sync::Mutex<Option<NetworkNamespaceRef>> = std::sync::Mutex::new(None);

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
    let _ = net::net_ns::install_final_drop_pending_notifier();
    let opened_in = network_namespace::allocate(0).unwrap();
    let switched_to = network_namespace::allocate(0).unwrap();
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
