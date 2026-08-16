// Publishing an interface to the network stack, and the delivery hook that
// carries received frames the other way.
//
// The two directions are installed together and taken down together. An
// interface published for transmit but with no delivery hook receives
// nothing; a hook installed against an unpublished interface delivers into a
// stack that has no interface to attribute the frame to.

extern crate alloc;

use alloc::sync::Arc;

use net::NetIfaceId;

use super::convert::EthFrame;
use super::dev::{RxDeliver, WirelessNetDev};
use crate::iface::Sdata;

/// The delivery hook of a published interface.
pub struct StackDeliver {
    iface: NetIfaceId,
    dev: Arc<WirelessNetDev>,
}

impl RxDeliver for StackDeliver {
    /// # C: O(len)
    fn deliver_eth(&self, eth: &EthFrame) {
        let frame = eth.to_bytes();
        self.deliver_raw(&frame);
    }
    /// # C: O(len)
    fn deliver_raw(&self, frame: &[u8]) {
        let stack = net::global_stack();
        let owner: Arc<dyn net::NetDev> = self.dev.clone();
        let Some(lease) = stack.ifaces.acquire_ingress_for(self.iface, &owner) else { return; };
        let _ = stack.deliver_ethernet_in(&lease, frame);
    }
}

/// Publish an interface and install its delivery hook. # C: O(N interfaces)
pub fn register(sdata: &Arc<Sdata>) -> Option<NetIfaceId> {
    if !sdata.iftype().has_netdev() { return None; }
    let dev = WirelessNetDev::new(sdata);
    let owner: Arc<dyn net::NetDev> = dev.clone();
    let stack = net::global_stack();
    let namespace = net::net_ns::initial_namespace();
    let reg = stack.prepare_iface(owner, &namespace)?;
    let id = reg.id();
    if !stack.publish_iface(reg) { return None; }
    *sdata.deliver.lock() = Some(Arc::new(StackDeliver { iface: id, dev }));
    sdata.wdev.with(|w| w.ifindex = Some(id.raw()));
    Some(id)
}

/// Withdraw an interface and drop its delivery hook. # C: O(N interfaces)
pub fn unregister(sdata: &Arc<Sdata>, iface: NetIfaceId) {
    *sdata.deliver.lock() = None;
    sdata.wdev.with(|w| w.ifindex = None);
    net::global_stack().unregister_iface(iface);
}
