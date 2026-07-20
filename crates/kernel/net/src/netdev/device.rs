// Device contract — driver-facing link identity, transmit, namespace, and
// packet-filter ownership. The interface registry owns publication and
// generation lifetime; this module owns no registry state.

use crate::addr::MacAddr;
use crate::pkt::{Pkt, DEFAULT_HEADROOM};

use super::{IfaceMap, NamespaceDropAction, NetError, NetResult, NetStats};
use super::packet_filter::PacketRxMode;

/// `25§3` driver trait.
pub trait NetDev: Send + Sync {
    /// Stable interface name (`lo`, `eth0`, …).
    fn name(&self) -> &str;
    /// Hardware MAC. Loopback returns ZERO.
    fn mac(&self) -> MacAddr;
    /// Link-layer broadcast address used by receive packet classification. # C: O(1)
    fn broadcast(&self) -> MacAddr { MacAddr::BROADCAST }
    /// Maximum L2 payload size in bytes (1500 default; 65535 for lo).
    fn mtu(&self) -> u32;
    /// Apply Linux `ndo_change_mtu` to the canonical device owner. # C: O(1)
    fn set_mtu(&self, _mtu: u32) -> NetResult<()> { Err(NetError::Eopnotsupp) }
    /// Apply Linux `ndo_set_mac_address` to the canonical device owner. # C: O(1)
    fn set_mac(&self, _mac: MacAddr) -> NetResult<()> { Err(NetError::Eopnotsupp) }
    /// Linux `net_device::tx_queue_len`, read from the device owner. # C: O(1)
    fn tx_queue_len(&self) -> u32 { 1000 }
    /// Update Linux `net_device::tx_queue_len` under the device owner. # C: O(1)
    fn set_tx_queue_len(&self, _len: u32) -> NetResult<()> { Err(NetError::Eopnotsupp) }
    /// Linux `net_device` private interface flags, owned by the device. # C: O(1)
    fn private_flags(&self) -> Option<u16> { None }
    /// Update Linux private interface flags under the device owner. # C: O(1)
    fn set_private_flags(&self, _flags: u16) -> NetResult<()> { Err(NetError::Eopnotsupp) }
    /// Link address width used by packet membership validation. # C: O(1)
    fn address_len(&self) -> u8 { 6 }
    /// Linux ARPHRD type exposed by link-layer socket metadata. # C: O(1)
    fn hardware_type(&self) -> u16 { crate::uapi::ARPHRD_ETHER }
    /// Linux `SIOCGIFMAP` resource coordinates, owned by the device. # C: O(1)
    fn ifmap(&self) -> IfaceMap { IfaceMap::default() }
    /// Apply the canonical packet receive filter snapshot. # C: driver-dependent
    fn packet_rx_mode_changed(&self, _mode: &PacketRxMode) {}
    /// Hand a packet to the device for transmit. # C: O(packet)
    fn xmit(&self, pkt: Pkt) -> NetResult<()>;
    /// Transmit while exposing the exact user-visible packet view before device ownership transfer.
    /// Drivers that add a link header override this and report the completed frame. # C: O(packet)
    fn xmit_observed(&self, pkt: Pkt, observe: &mut dyn FnMut(&[u8], u16, usize)) -> NetResult<()> {
        let protocol = pkt.proto;
        observe(pkt.data(), protocol, 0);
        self.xmit(pkt)
    }
    /// Transmit an L3 packet after its canonical neighbour owner selected the destination MAC.
    /// Ethernet-capable drivers override this; default preserves non-Ethernet device semantics. # C: O(packet)
    fn xmit_l2_observed(&self, pkt: Pkt, _dst: MacAddr,
                        observe: &mut dyn FnMut(&[u8], u16, usize)) -> NetResult<()> {
        self.xmit_observed(pkt, observe)
    }
    /// Transmit a complete L2 frame verbatim. # C: O(len)
    fn xmit_raw(&self, frame: &[u8]) -> NetResult<()> {
        let mut pkt = Pkt::new_with_headroom(DEFAULT_HEADROOM, frame.len());
        pkt.data_mut().copy_from_slice(frame);
        self.xmit(pkt)
    }
    /// Bypass packet scheduling for one already-built link frame. # C: O(len)
    fn xmit_raw_direct(&self, frame: &[u8]) -> NetResult<()> { self.xmit_raw(frame) }
    /// Drop device-private state owned by a departing network namespace. # C: O(device namespace state)
    fn retire_namespace(&self);
    /// Resume device-private work after reassignment to the initial namespace. # C: O(1)
    fn resume_namespace(&self) {}
    /// Device disposition when its current network namespace is destroyed. # C: O(1)
    fn namespace_drop_action(&self) -> NamespaceDropAction;
    /// Apply primary IPv4 state to device-private receive/control runtime. # C: O(device runtime lookup)
    fn ipv4_addr_changed(&self, _addr: Option<crate::Ipv4Addr>) {}
    /// Snapshot the per-iface running counters. # C: O(1)
    fn stats(&self) -> NetStats { NetStats::default() }
}
