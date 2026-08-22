// One VLAN interface: the identity it publishes, the tag it adds on the way
// out, and the translation it applies on the way in. The lower interface does
// the actual transmit; nothing here keeps a second copy of its state.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use net::addr::{MacAddr, NetIfaceId};
use net::ethernet::EthHdr;
use net::netdev::{NamespaceDropAction, NetDev, NetError, NetResult, NetStats};
use net::pkt::Pkt;
use sync::{Socket as SocketLockClass, Spinlock};
use syscall::errno::Errno;

use crate::caps::{check_mtu, inherit_mac, RealDevCaps};
use crate::flags::{reorder_hdr, VLAN_FLAG_DEFAULT};
use crate::prio::PrioMaps;
use crate::tci;
use crate::uapi::{ARPHRD_ETHER, ETH_HLEN, VLAN_VID_MASK};
use crate::xmit::{apply, egress_tag_mode, EgressFrame};

/// Disposition of a tagged frame the lower interface received.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IngressResult {
    /// Interface is administratively down; the frame goes no further.
    Dropped,
    /// Frame belongs to this interface, in the form it should be delivered in,
    /// with the transmit priority its code point selected.
    Deliver { frame: Vec<u8>, priority: u32 },
}

/// Form a received frame takes on delivery: detagged, unless this interface
/// wants the tag back inside the bytes. # C: O(len)
pub fn ingress_frame(flags: u32, frame: &[u8]) -> Result<Vec<u8>, tci::TagError> {
    if reorder_hdr(flags) { Ok(tci::strip(frame)?.2) } else { Ok(frame.to_vec()) }
}

pub struct VlanDev {
    name: String,
    vlan_id: u16,
    vlan_proto: u16,
    real_id: NetIfaceId,
    real: Arc<dyn NetDev>,
    caps: RealDevCaps,
    flags: AtomicU32,
    mtu: AtomicU32,
    up: AtomicBool,
    mac: Spinlock<MacAddr, SocketLockClass>,
    maps: Spinlock<PrioMaps, SocketLockClass>,
    stats: Spinlock<NetStats, SocketLockClass>,
}

impl VlanDev {
    /// Build an interface for one identifier on one lower interface. The frame
    /// size starts at the largest the lower interface leaves room for, and the
    /// address is the lower interface's unless one was asked for.
    /// # C: O(1)
    pub fn new(name: String, vlan_id: u16, vlan_proto: u16, real_id: NetIfaceId,
               real: Arc<dyn NetDev>, caps: RealDevCaps, mac: MacAddr) -> Self {
        Self {
            name, vlan_id: vlan_id & VLAN_VID_MASK, vlan_proto, real_id, real, caps,
            flags: AtomicU32::new(VLAN_FLAG_DEFAULT),
            mtu: AtomicU32::new(crate::caps::max_mtu(&caps)),
            up: AtomicBool::new(false),
            mac: Spinlock::new(inherit_mac(mac, &caps)),
            maps: Spinlock::new(PrioMaps::new()),
            stats: Spinlock::new(NetStats::default()),
        }
    }

    /// # C: O(1)
    pub fn vlan_id(&self) -> u16 { self.vlan_id }
    /// # C: O(1)
    pub fn vlan_proto(&self) -> u16 { self.vlan_proto }
    /// Lower interface this one is stacked on. # C: O(1)
    pub fn real_id(&self) -> NetIfaceId { self.real_id }
    /// # C: O(1)
    pub fn flags(&self) -> u32 { self.flags.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn set_flags(&self, value: u32) { self.flags.store(value, Ordering::Release); }
    /// Fold a `{flags, mask}` request into the current word. # C: O(1)
    pub fn change_flags(&self, value: u32, mask: u32) -> Result<u32, Errno> {
        let next = crate::flags::change(self.flags(), value, mask)?;
        self.set_flags(next);
        Ok(next)
    }
    /// # C: O(1)
    pub fn is_up(&self) -> bool { self.up.load(Ordering::Acquire) }

    /// Run a closure over the priority tables under their lock. # C: O(closure)
    pub fn with_maps<R>(&self, f: impl FnOnce(&mut PrioMaps) -> R) -> R {
        f(&mut self.maps.lock())
    }

    /// Tag control information for a frame leaving at this transmit priority.
    /// # C: O(bucket length)
    pub fn egress_tci(&self, priority: u32) -> u16 {
        self.vlan_id | self.maps.lock().egress_mask(priority)
    }

    /// Tag a built link frame for transmission. `outer_ethertype` is `None`
    /// when this interface built the header itself. # C: O(len)
    pub fn egress(&self, frame: &[u8], outer_ethertype: Option<u16>, priority: u32)
        -> Result<EgressFrame, tci::TagError>
    {
        let mode = egress_tag_mode(self.flags(), outer_ethertype, self.vlan_proto);
        apply(mode, frame, self.vlan_proto, self.egress_tci(priority),
              self.caps.hw_tag_insert_for(self.vlan_proto))
    }

    /// Accept one tagged frame the lower interface received for this
    /// interface. The caller has already matched the tag to this interface.
    /// # C: O(len)
    pub fn ingress(&self, frame: &[u8], tci_value: u16) -> IngressResult {
        if !self.is_up() { return IngressResult::Dropped; }
        let Ok(out) = ingress_frame(self.flags(), frame) else { return IngressResult::Dropped };
        let priority = self.maps.lock().ingress_for_tci(tci_value);
        let mut stats = self.stats.lock();
        stats.rx_packets += 1;
        stats.rx_bytes += out.len() as u64;
        IngressResult::Deliver { frame: out, priority }
    }

    /// Tag a complete link frame and hand it to the lower interface. # C: O(len)
    fn send_frame(&self, frame: &[u8], priority: u32) -> NetResult<()> {
        let outer = (frame.len() >= ETH_HLEN)
            .then(|| u16::from_be_bytes([frame[ETH_HLEN - 2], frame[ETH_HLEN - 1]]));
        let out = self.egress(frame, outer, priority).map_err(|_| NetError::Einval)?;
        let result = match out.hw_tag {
            Some((proto, tci)) => self.real.xmit_vlan(&out.frame, proto, tci),
            None => self.real.xmit_raw(&out.frame),
        };
        let mut stats = self.stats.lock();
        if result.is_ok() { stats.tx_packets += 1; stats.tx_bytes += out.frame.len() as u64; }
        else { stats.tx_dropped += 1; }
        result
    }
}

impl NetDev for VlanDev {
    fn name(&self) -> &str { &self.name }
    fn mac(&self) -> MacAddr { *self.mac.lock() }
    fn mtu(&self) -> u32 { self.mtu.load(Ordering::Acquire) }
    fn hardware_type(&self) -> u16 { ARPHRD_ETHER }

    /// # C: O(1)
    fn set_mtu(&self, mtu: u32) -> NetResult<()> {
        match check_mtu(&self.caps, mtu) {
            Ok(value) => { self.mtu.store(value, Ordering::Release); Ok(()) }
            Err(_) => Err(NetError::Erange),
        }
    }

    /// # C: O(1)
    fn set_mac(&self, mac: MacAddr) -> NetResult<()> { *self.mac.lock() = mac; Ok(()) }

    /// # C: O(1)
    fn admin_up_changed(&self, up: bool) { self.up.store(up, Ordering::Release); }

    /// The packet body is a complete link frame; tagging is all this interface
    /// adds. # C: O(len)
    fn xmit(&self, pkt: Pkt) -> NetResult<()> { self.send_frame(pkt.data(), pkt.tx.priority) }

    /// # C: O(len)
    fn xmit_raw(&self, frame: &[u8]) -> NetResult<()> { self.send_frame(frame, 0) }

    /// Build the link header with this interface's own address, then tag.
    /// # C: O(len)
    fn xmit_l2_observed(&self, pkt: Pkt, dst: MacAddr,
                        observe: &mut dyn FnMut(&[u8], u16, usize)) -> NetResult<()> {
        let body = pkt.data();
        let mut frame = alloc::vec![0u8; ETH_HLEN + body.len()];
        EthHdr::write_to(dst, self.mac(), pkt.proto, &mut frame[..ETH_HLEN]);
        frame[ETH_HLEN..].copy_from_slice(body);
        let out = self.egress(&frame, None, pkt.tx.priority).map_err(|_| NetError::Einval)?;
        observe(&out.frame, pkt.proto, out.frame.len() - body.len());
        let result = match out.hw_tag {
            Some((proto, tci)) => self.real.xmit_vlan(&out.frame, proto, tci),
            None => self.real.xmit_raw(&out.frame),
        };
        let mut stats = self.stats.lock();
        if result.is_ok() { stats.tx_packets += 1; stats.tx_bytes += out.frame.len() as u64; }
        else { stats.tx_dropped += 1; }
        result
    }

    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> NamespaceDropAction { NamespaceDropAction::Destroy }
    fn stats(&self) -> NetStats { *self.stats.lock() }
}
