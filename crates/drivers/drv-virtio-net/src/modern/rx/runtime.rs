use alloc::sync::Arc;

use sync::{Spinlock, TaskList as DriverLockClass};

use super::super::DeviceKey;

#[derive(Clone)]
pub(super) struct RxRuntime {
    pub(super) device_key: DeviceKey,
    pub(super) iface: net::NetIfaceId,
    pub(super) owner: Arc<dyn net::NetDev>,
    pub(super) generation: u64,
    pub(super) net_runtime: Arc<super::super::netdev::NetRuntime>,
    pub(super) ip: [u8; 4],
}

static RX_RUNTIMES: Spinlock<alloc::vec::Vec<RxRuntime>, DriverLockClass> =
    Spinlock::new(alloc::vec::Vec::new());

/// Stash one device's RX identity and network runtime. # C: O(1)
pub(crate) fn set_softirq_iface(device_key: DeviceKey, iface: net::NetIfaceId,
                                owner: Arc<dyn net::NetDev>, generation: u64,
                                net_runtime: Arc<super::super::netdev::NetRuntime>, ip: [u8; 4]) {
    let mut runtimes = RX_RUNTIMES.lock();
    if let Some(runtime) = runtimes.iter_mut().find(|runtime| runtime.device_key == device_key) {
        *runtime = RxRuntime { device_key, iface, owner, generation, net_runtime, ip };
        return;
    }
    runtimes.push(RxRuntime { device_key, iface, owner, generation, net_runtime, ip });
}

/// Install one device's RX runtime and shared handlers. # C: O(1)
pub(crate) fn install_rx_runtime(device_key: DeviceKey, iface: net::NetIfaceId,
                                 owner: Arc<dyn net::NetDev>, generation: u64,
                                 net_runtime: Arc<super::super::netdev::NetRuntime>) {
    set_softirq_iface(device_key, iface, owner, generation, net_runtime, [0, 0, 0, 0]);
    super::install_rx_softirq_handler();
}

/// Snapshot device runtimes for one softirq drain. # C: O(N devices)
pub(super) fn snapshot() -> alloc::vec::Vec<RxRuntime> { RX_RUNTIMES.lock().clone() }

/// Retain the matching network runtime for one RX poll. # C: O(N devices)
pub(super) fn net_runtime_for(device_key: DeviceKey, owner: &Arc<dyn net::NetDev>,
                              generation: u64) -> Option<Arc<super::super::netdev::NetRuntime>> {
    RX_RUNTIMES.lock().iter().find(|runtime| runtime.device_key == device_key
        && Arc::ptr_eq(&runtime.owner, owner) && runtime.generation == generation)
        .map(|runtime| runtime.net_runtime.clone())
}

/// Update only the IP slot owned by one transport device. # C: O(N devices)
pub(crate) fn set_softirq_ip_for_owner(device_key: DeviceKey, owner: &dyn net::NetDev,
                                       ip: [u8; 4]) -> bool {
    let mut runtimes = RX_RUNTIMES.lock();
    let Some(runtime) = runtimes.iter_mut().find(|runtime| runtime.device_key == device_key
        && core::ptr::addr_eq(runtime.owner.as_ref(), owner)) else { return false; };
    runtime.ip = ip;
    true
}

#[cfg(test)]
/// Update one retained test runtime by interface identity. # C: O(N devices)
pub(crate) fn set_softirq_ip_for_iface(iface: net::NetIfaceId, ip: [u8; 4]) -> bool {
    let mut runtimes = RX_RUNTIMES.lock();
    let Some(runtime) = runtimes.iter_mut().find(|runtime| runtime.iface == iface)
        else { return false; };
    runtime.ip = ip;
    true
}

/// Clear one device's configured IP without changing its assignment. # C: O(N devices)
pub(crate) fn clear_softirq_ip_for_owner(device_key: DeviceKey, owner: &dyn net::NetDev) {
    if let Some(runtime) = RX_RUNTIMES.lock().iter_mut()
        .find(|runtime| runtime.device_key == device_key
            && core::ptr::addr_eq(runtime.owner.as_ref(), owner)) {
        runtime.ip = [0, 0, 0, 0];
    }
}

/// Move one retained device runtime to a new assignment generation. # C: O(N devices)
pub(crate) fn set_rx_generation_for_owner(device_key: DeviceKey, owner: &dyn net::NetDev,
                                           generation: u64) {
    if let Some(runtime) = RX_RUNTIMES.lock().iter_mut()
        .find(|runtime| runtime.device_key == device_key
            && core::ptr::addr_eq(runtime.owner.as_ref(), owner)) {
        runtime.generation = generation;
    }
}

/// Clear all retained RX runtimes in test teardown. # C: O(N devices)
pub(crate) fn clear_rx_runtime() { RX_RUNTIMES.lock().clear(); }

/// Remove one device runtime and report whether the registry became empty. # C: O(N devices)
pub(crate) fn remove_rx_runtime_for(device_key: DeviceKey) -> Option<bool> {
    let mut runtimes = RX_RUNTIMES.lock();
    let pos = runtimes.iter().position(|runtime| runtime.device_key == device_key)?;
    runtimes.remove(pos);
    Some(runtimes.is_empty())
}

/// Report whether no receive device runtime remains. # C: O(1)
pub(crate) fn rx_runtime_empty() -> bool { RX_RUNTIMES.lock().is_empty() }

/// Read one device's configured IPv4 address. # C: O(N devices)
pub(crate) fn first_iface_ip_for(device_key: DeviceKey) -> Option<net::Ipv4Addr> {
    RX_RUNTIMES.lock().iter().find(|runtime| runtime.device_key == device_key)
        .map(|runtime| net::Ipv4Addr::from_u32(u32::from_be_bytes(runtime.ip)))
}
