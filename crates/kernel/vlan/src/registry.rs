// Which interface a tag belongs to. This is the only thing keyed by
// (lower interface, tag protocol, identifier); the interfaces themselves live
// in the one network-interface table like every other interface.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use net::addr::NetIfaceId;
use sync::{Socket as SocketLockClass, Spinlock};
use syscall::errno::Errno;

use crate::dev::{IngressResult, VlanDev};
use crate::tci;
use crate::uapi::VLAN_VID_MASK;

/// What makes a VLAN interface unique. Two interfaces may share an identifier
/// as long as they sit on different lower interfaces or carry different tag
/// protocols.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VlanKey {
    pub real: NetIfaceId,
    pub proto: u16,
    pub vlan_id: u16,
}

impl VlanKey {
    /// # C: O(1)
    pub const fn new(real: NetIfaceId, proto: u16, vlan_id: u16) -> Self {
        Self { real, proto, vlan_id: vlan_id & VLAN_VID_MASK }
    }
}

/// Outcome of offering a received frame to the VLAN layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Demux {
    /// No interface claims this tag — or the frame carries none. The frame is
    /// untouched and still belongs to whoever received it.
    NotOurs,
    /// The claiming interface refused the frame.
    Dropped,
    /// The frame is now this interface's, in the delivered form.
    Deliver { iface: NetIfaceId, frame: Vec<u8>, priority: u32 },
}

struct Row {
    key: VlanKey,
    iface: NetIfaceId,
    dev: Arc<VlanDev>,
}

/// Tag-to-interface table.
pub struct VlanTable {
    rows: Spinlock<Vec<Row>, SocketLockClass>,
}

impl Default for VlanTable {
    fn default() -> Self { Self::new() }
}

impl VlanTable {
    /// # C: O(1)
    pub const fn new() -> Self { Self { rows: Spinlock::new(Vec::new()) } }

    /// Whether an interface already claims this tag. # C: O(N)
    pub fn contains(&self, key: &VlanKey) -> bool {
        self.rows.lock().iter().any(|r| r.key == *key)
    }

    /// Claim a tag for an interface. A tag is claimed once: a second interface
    /// for the same identifier on the same lower interface already exists.
    /// # C: O(N)
    pub fn insert(&self, iface: NetIfaceId, dev: Arc<VlanDev>) -> Result<VlanKey, Errno> {
        let key = VlanKey::new(dev.real_id(), dev.vlan_proto(), dev.vlan_id());
        let mut rows = self.rows.lock();
        if rows.iter().any(|r| r.key == key) { return Err(Errno::Eexist); }
        rows.push(Row { key, iface, dev });
        Ok(key)
    }

    /// Release the tag an interface claimed. # C: O(N)
    pub fn remove(&self, iface: NetIfaceId) -> Option<Arc<VlanDev>> {
        let mut rows = self.rows.lock();
        let pos = rows.iter().position(|r| r.iface == iface)?;
        Some(rows.remove(pos).dev)
    }

    /// Interface claiming one tag. # C: O(N)
    pub fn find(&self, key: &VlanKey) -> Option<(NetIfaceId, Arc<VlanDev>)> {
        self.rows.lock().iter().find(|r| r.key == *key).map(|r| (r.iface, r.dev.clone()))
    }

    /// The VLAN interface behind one interface handle. # C: O(N)
    pub fn by_iface(&self, iface: NetIfaceId) -> Option<Arc<VlanDev>> {
        self.rows.lock().iter().find(|r| r.iface == iface).map(|r| r.dev.clone())
    }

    /// Every VLAN interface stacked on one lower interface, for the teardown
    /// that follows the lower interface's removal. # C: O(N)
    pub fn on_real(&self, real: NetIfaceId) -> Vec<(NetIfaceId, Arc<VlanDev>)> {
        self.rows.lock().iter().filter(|r| r.key.real == real)
            .map(|r| (r.iface, r.dev.clone())).collect()
    }

    /// Offer a frame the lower interface received to the VLAN layer.
    /// # C: O(N + len)
    pub fn demux(&self, real: NetIfaceId, frame: &[u8]) -> Demux {
        let Ok((proto, tci_value)) = tci::peek(frame) else { return Demux::NotOurs };
        let key = VlanKey::new(real, proto, tci::vlan_id(tci_value));
        let Some((iface, dev)) = self.find(&key) else { return Demux::NotOurs };
        match dev.ingress(frame, tci_value) {
            IngressResult::Dropped => Demux::Dropped,
            IngressResult::Deliver { frame, priority } =>
                Demux::Deliver { iface, frame, priority },
        }
    }
}

static TABLE: VlanTable = VlanTable::new();

/// The kernel's one tag-to-interface table. # C: O(1)
pub fn table() -> &'static VlanTable { &TABLE }
