use super::super::*;

struct RxTestOwner;

impl net::NetDev for RxTestOwner {
    fn name(&self) -> &str { "rx-test" }
    fn mac(&self) -> net::MacAddr { net::MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, _pkt: net::Pkt) -> net::NetResult<()> { Ok(()) }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> net::NamespaceDropAction {
        net::NamespaceDropAction::Destroy
    }
}

fn rx_test_owner(device_key: DeviceKey) -> alloc::sync::Arc<dyn net::NetDev> {
    VirtioNetDev::new_for(device_key)
        .map(|dev| dev as alloc::sync::Arc<dyn net::NetDev>)
        .unwrap_or_else(|| alloc::sync::Arc::new(RxTestOwner))
}

pub(super) fn set_test_rx(device_key: DeviceKey, iface: net::NetIfaceId,
                          ip: [u8; 4]) -> alloc::sync::Arc<dyn net::NetDev> {
    let runtime = ensure_net_runtime(device_key);
    let generation = runtime.rx_assignments.current();
    let owner = rx_test_owner(device_key);
    set_softirq_iface(device_key, iface, owner.clone(), generation, runtime, ip);
    owner
}

pub(super) fn install_test_rx(device_key: DeviceKey, iface: net::NetIfaceId)
    -> alloc::sync::Arc<dyn net::NetDev>
{
    let runtime = ensure_net_runtime(device_key);
    let generation = runtime.rx_assignments.current();
    let owner = rx_test_owner(device_key);
    install_rx_runtime(device_key, iface, owner.clone(), generation, runtime);
    owner
}
