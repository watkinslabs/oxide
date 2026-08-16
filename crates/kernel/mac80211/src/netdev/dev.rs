// The network device a managed-mode wireless interface presents.
//
// Everything above this layer sees an Ethernet interface, because that is
// what a wireless station is to a network stack: the 802.11 header, the
// encapsulation, the sequence numbers and the ciphers all stop here. The
// conversion in `convert` is what makes that true, and this file is what
// attaches it to the stack.

extern crate alloc;

use alloc::string::String;
use alloc::sync::{Arc, Weak};

use net::netdev::{NamespaceDropAction, NetError, NetResult, NetStats};
use net::{MacAddr as NetMac, NetDev, Pkt};

use super::convert::EthFrame;
use crate::iface::Sdata;
use crate::uapi;

/// Where a converted received frame goes. An interface installs one of these
/// when it is published; the receive chain calls it and knows nothing about
/// what is on the other side.
pub trait RxDeliver: Send + Sync {
    /// Deliver one converted Ethernet frame. # C: O(len)
    fn deliver_eth(&self, eth: &EthFrame);
    /// Deliver one whole 802.11 frame, for a monitor interface. # C: O(len)
    fn deliver_raw(&self, _frame: &[u8]) {}
}

/// The device one interface is published as.
pub struct WirelessNetDev {
    name: String,
    addr: NetMac,
    /// The interface. Weak because the interface owns the delivery hook that
    /// owns this device.
    sdata: Weak<Sdata>,
}

impl WirelessNetDev {
    /// Build a device for an interface. # C: O(len)
    pub fn new(sdata: &Arc<Sdata>) -> Arc<Self> {
        Arc::new(Self {
            name: sdata.name(),
            addr: NetMac(sdata.addr.0),
            sdata: Arc::downgrade(sdata),
        })
    }

    fn iface(&self) -> Option<Arc<Sdata>> { self.sdata.upgrade() }

    /// Send one Ethernet frame down the transmit chain. # C: O(len)
    fn send(&self, eth: &EthFrame) -> NetResult<()> {
        let Some(sdata) = self.iface() else { return Err(NetError::Enodev); };
        let Some(local) = sdata.local() else { return Err(NetError::Enodev); };
        if !sdata.is_up() { return Err(NetError::Enetdown); }
        if crate::tx::xmit_eth(&local, &sdata, eth) { Ok(()) } else { Err(NetError::Eio) }
    }
}

impl NetDev for WirelessNetDev {
    fn name(&self) -> &str { self.name.as_str() }
    fn mac(&self) -> NetMac { self.addr }
    fn mtu(&self) -> u32 { uapi::ETH_DATA_LEN as u32 }
    fn hardware_type(&self) -> u16 { uapi::ARPHRD_ETHER }

    /// A frame with no resolved destination cannot go out over the air: an
    /// 802.11 header names the peer explicitly and there is no equivalent of
    /// putting it on a shared wire and letting the right station pick it up.
    /// The stack's resolved path and its raw path are the two that carry
    /// traffic. # C: O(1)
    fn xmit(&self, _pkt: Pkt) -> NetResult<()> { Err(NetError::Eopnotsupp) }

    fn xmit_l2_observed(&self, pkt: Pkt, dst: NetMac,
                        observe: &mut dyn FnMut(&[u8], u16, usize)) -> NetResult<()> {
        let eth = EthFrame {
            dst: wireless::ieee80211::MacAddr(dst.0),
            src: wireless::ieee80211::MacAddr(self.addr.0),
            proto: pkt.proto,
            payload: pkt.data().to_vec(),
        };
        let frame = eth.to_bytes();
        observe(&frame, pkt.proto, uapi::ETH_HDR_LEN);
        self.send(&eth)
    }

    fn xmit_raw(&self, frame: &[u8]) -> NetResult<()> {
        let Some(eth) = EthFrame::parse(frame) else { return Err(NetError::Einval); };
        self.send(&eth)
    }

    fn retire_namespace(&self) {}

    /// A radio belongs to the machine, not to a namespace that went away, so
    /// its interface comes back to the initial namespace rather than being
    /// destroyed with the one that held it. # C: O(1)
    fn namespace_drop_action(&self) -> NamespaceDropAction { NamespaceDropAction::MoveToInitial }

    fn admin_up_changed(&self, up: bool) {
        let Some(sdata) = self.iface() else { return; };
        let Some(local) = sdata.local() else { return; };
        if up { let _ = crate::iface::up(&local, &sdata); } else { crate::iface::down(&local, &sdata); }
    }

    fn stats(&self) -> NetStats {
        let Some(sdata) = self.iface() else { return NetStats::default(); };
        let s = sdata.stats();
        let mut out = NetStats::default();
        out.rx_packets = s.rx_packets;
        out.rx_bytes = s.rx_bytes;
        out.rx_dropped = s.rx_dropped;
        out.tx_packets = s.tx_packets;
        out.tx_bytes = s.tx_bytes;
        out.tx_dropped = s.tx_dropped;
        out
    }
}
