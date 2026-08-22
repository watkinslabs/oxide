// Fixtures: a lower interface that records what it was handed, and builders
// for the frames and attribute blobs the tests feed in.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use net::addr::{MacAddr, NetIfaceId};
use net::netdev::{NamespaceDropAction, NetDev, NetDevFeatures, NetResult};
use net::pkt::Pkt;
use sync::{Socket as SocketLockClass, Spinlock};

use crate::caps::RealDevCaps;
use crate::dev::VlanDev;
use crate::uapi::{nla_align, ARPHRD_ETHER, ETH_HLEN, NLA_HDR_LEN};

pub struct FakeDev {
    pub name: String,
    pub mac: MacAddr,
    pub mtu: u32,
    pub hardware_type: u16,
    pub sent: Spinlock<Vec<Vec<u8>>, SocketLockClass>,
    pub features: NetDevFeatures,
    pub vlan_tags: Spinlock<Vec<(u16, u16)>, SocketLockClass>,
}

impl FakeDev {
    pub fn new(name: &str, mac: [u8; 6], mtu: u32) -> Arc<Self> {
        Arc::new(Self {
            name: String::from(name), mac: MacAddr(mac), mtu,
            hardware_type: ARPHRD_ETHER, sent: Spinlock::new(Vec::new()),
            features: NetDevFeatures::NONE, vlan_tags: Spinlock::new(Vec::new()),
        })
    }
    pub fn frames(&self) -> Vec<Vec<u8>> { self.sent.lock().clone() }
    pub fn tags(&self) -> Vec<(u16, u16)> { self.vlan_tags.lock().clone() }
}

impl NetDev for FakeDev {
    fn name(&self) -> &str { &self.name }
    fn mac(&self) -> MacAddr { self.mac }
    fn mtu(&self) -> u32 { self.mtu }
    fn hardware_type(&self) -> u16 { self.hardware_type }
    fn features(&self) -> NetDevFeatures { self.features }
    fn xmit(&self, pkt: Pkt) -> NetResult<()> { self.xmit_raw(pkt.data()) }
    fn xmit_raw(&self, frame: &[u8]) -> NetResult<()> {
        self.sent.lock().push(frame.to_vec());
        Ok(())
    }
    fn xmit_vlan(&self, frame: &[u8], proto: u16, tci: u16) -> NetResult<()> {
        self.vlan_tags.lock().push((proto, tci));
        self.sent.lock().push(frame.to_vec());
        Ok(())
    }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> NamespaceDropAction { NamespaceDropAction::Destroy }
}

pub const REAL_MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

/// Properties of a plain Ethernet lower interface.
pub fn plain_caps(mtu: u32) -> RealDevCaps {
    RealDevCaps {
        mtu, hardware_type: ARPHRD_ETHER, mac: MacAddr(REAL_MAC),
        vlan_challenged: false, reduces_vlan_mtu: false, hw_tag_insert: false,
        features: NetDevFeatures::NONE,
    }
}

/// A VLAN interface on a fresh fake lower interface, brought up.
pub fn vlan_on(real: &Arc<FakeDev>, vlan_id: u16, proto: u16) -> Arc<VlanDev> {
    let caps = RealDevCaps::from_netdev(real.as_ref());
    let dev = Arc::new(VlanDev::new(
        String::from("eth0.test"), vlan_id, proto, NetIfaceId(7),
        real.clone() as Arc<dyn NetDev>, caps, MacAddr::ZERO));
    dev.admin_up_changed(true);
    dev
}

/// Untagged Ethernet frame with a body of `len` incrementing bytes.
pub fn eth_frame(dst: [u8; 6], src: [u8; 6], ethertype: u16, len: usize) -> Vec<u8> {
    let mut frame = alloc::vec![0u8; ETH_HLEN + len];
    frame[..6].copy_from_slice(&dst);
    frame[6..12].copy_from_slice(&src);
    frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
    for (i, b) in frame[ETH_HLEN..].iter_mut().enumerate() { *b = i as u8; }
    frame
}

/// One attribute, padded.
pub fn attr(ty: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let total = NLA_HDR_LEN + payload.len();
    out.extend_from_slice(&(total as u16).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(payload);
    while out.len() < nla_align(total) { out.push(0); }
    out
}

pub fn attr_u16(ty: u16, v: u16) -> Vec<u8> { attr(ty, &v.to_ne_bytes()) }
pub fn attr_be16(ty: u16, v: u16) -> Vec<u8> { attr(ty, &v.to_be_bytes()) }

pub fn attr_flags(ty: u16, flags: u32, mask: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&flags.to_ne_bytes());
    payload.extend_from_slice(&mask.to_ne_bytes());
    attr(ty, &payload)
}

pub fn attr_mapping(from: u32, to: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&from.to_ne_bytes());
    payload.extend_from_slice(&to.to_ne_bytes());
    attr(crate::uapi::IFLA_VLAN_QOS_MAPPING, &payload)
}

pub fn nest(ty: u16, children: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for c in children { payload.extend_from_slice(c); }
    attr(ty, &payload)
}

pub fn blob(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts { out.extend_from_slice(p); }
    out
}
