//! Bridge `NetDev` identity; forwarding and FDB ownership remain in `bridge`.

use alloc::string::String;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::{MacAddr, NamespaceDropAction, NetDev, NetError, NetResult, Pkt};

static NEXT_BRIDGE_MAC: AtomicU32 = AtomicU32::new(1);

/// A Linux bridge is a first-class link device, not an ioctl-only table row.
pub(crate) struct BridgeDev {
    name: String,
    mac: MacAddr,
    iface: AtomicU32,
}

impl BridgeDev {
    pub(crate) fn new(name: &str) -> Self {
        let serial = NEXT_BRIDGE_MAC.fetch_add(1, Ordering::Relaxed);
        Self { name: String::from(name), mac: MacAddr([
            0x02, 0x00, (serial >> 16) as u8, (serial >> 8) as u8, serial as u8, 0x01,
        ]), iface: AtomicU32::new(0) }
    }

    pub(crate) fn set_iface(&self, iface: crate::NetIfaceId) {
        self.iface.store(iface.raw(), Ordering::Release);
    }
}

impl NetDev for BridgeDev {
    fn name(&self) -> &str { &self.name }
    fn mac(&self) -> MacAddr { self.mac }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, _packet: Pkt) -> NetResult<()> {
        // The bridge transmit owner is installed together with bridge-neighbor
        // state; accepting L3 packets before that would lose their destination MAC.
        Err(NetError::Eopnotsupp)
    }
    fn xmit_raw(&self, frame: &[u8]) -> NetResult<()> {
        let iface = self.iface.load(Ordering::Acquire);
        if iface == 0 { return Err(NetError::Enodev); }
        crate::global_stack().bridge_xmit_raw(crate::NetIfaceId::from_raw(iface), frame)
    }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> NamespaceDropAction { NamespaceDropAction::Destroy }
}
