// What the lower interface can do, and the three rules a VLAN interface
// derives from it: whether it may exist at all, how large its frames may be,
// and which address it starts with.

use net::addr::MacAddr;
use net::netdev::{NetDev, NetDevFeatures};
use syscall::errno::Errno;

use crate::uapi::{ARPHRD_ETHER, VLAN_HLEN};

/// The lower interface's properties, read once so every rule below is a pure
/// function of them.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RealDevCaps {
    pub mtu: u32,
    pub hardware_type: u16,
    pub mac: MacAddr,
    /// Interface cannot carry tagged frames at all.
    pub vlan_challenged: bool,
    /// Interface spends the tag's 4 bytes out of its own frame budget, so a
    /// VLAN above it gets a smaller maximum than the lower interface has.
    pub reduces_vlan_mtu: bool,
    /// Interface inserts the tag itself when handed one out of band. Without
    /// it the tag is pushed into the frame before the interface sees it.
    pub hw_tag_insert: bool,
    /// Full lower-device feature word, retained so CTAG and STAG decisions
    /// remain protocol-specific after VLAN creation.
    pub features: NetDevFeatures,
}

impl RealDevCaps {
    /// Read the properties of a live lower interface.
    ///
    /// The lower driver owns the feature word; this snapshot keeps one
    /// decision source for VLAN admission, MTU accounting, and tag placement.
    /// # C: O(1)
    pub fn from_netdev(dev: &dyn NetDev) -> Self {
        let features = dev.features();
        Self {
            mtu: dev.mtu(),
            hardware_type: dev.hardware_type(),
            mac: dev.mac(),
            vlan_challenged: features.has(net::netdev::NetDevFeatures::VLAN_CHALLENGED),
            reduces_vlan_mtu: features.has(net::netdev::NetDevFeatures::VLAN_MTU_REDUCED),
            hw_tag_insert: features.hw_vlan_tx(crate::uapi::ETH_P_8021Q)
                || features.hw_vlan_tx(crate::uapi::ETH_P_8021AD),
            features,
        }
    }

    /// Whether this lower device inserts the requested VLAN protocol. # C: O(1)
    pub const fn hw_tag_insert_for(&self, proto: u16) -> bool {
        self.features.hw_vlan_tx(proto)
    }
}

/// Whether a VLAN interface may sit on this one. # C: O(1)
pub const fn check_real_dev(caps: &RealDevCaps) -> Result<(), Errno> {
    if caps.vlan_challenged || caps.hardware_type != ARPHRD_ETHER {
        return Err(Errno::Eopnotsupp);
    }
    Ok(())
}

/// Largest frame payload a VLAN interface on this lower interface may carry.
/// # C: O(1)
pub const fn max_mtu(caps: &RealDevCaps) -> u32 {
    if caps.reduces_vlan_mtu { caps.mtu.saturating_sub(VLAN_HLEN as u32) } else { caps.mtu }
}

/// Apply a requested frame size to a VLAN interface. Above what the lower
/// interface leaves room for is out of range, not merely invalid.
/// # C: O(1)
pub const fn check_mtu(caps: &RealDevCaps, requested: u32) -> Result<u32, Errno> {
    if requested > max_mtu(caps) { return Err(Errno::Erange); }
    Ok(requested)
}

/// Address a new VLAN interface starts with: its own when one was requested,
/// otherwise the lower interface's. # C: O(1)
pub fn inherit_mac(requested: MacAddr, caps: &RealDevCaps) -> MacAddr {
    if requested == MacAddr::ZERO { caps.mac } else { requested }
}
