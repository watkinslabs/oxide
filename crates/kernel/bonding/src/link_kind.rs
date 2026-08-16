//! The `bond` entry in the rtnetlink link-kind table, and the `bond` slave
//! kind that enslaves an interface into one. Without these the option parser,
//! the modes and the monitors have no caller: `ip link add bond0 type bond`
//! could not reach them.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use net::addr::NetIfaceId;
use rtnl_link::{LinkKindOps, LinkMsg};
use sync::{Socket as SocketLockClass, Spinlock};
use syscall::errno::Errno;

use crate::master::BondMaster;
use crate::netlink::{self, OptionWrite};
use crate::uapi::BOND_LINK_KIND;

struct Row { iface: NetIfaceId, bond: Arc<BondMaster> }

/// Bond masters by interface handle. This is an index onto the one interface
/// registry, not a second registry: the master is registered there like any
/// other device and this table only remembers which of them are bonds.
static BONDS: Spinlock<Vec<Row>, SocketLockClass> = Spinlock::new(Vec::new());

/// The bond master behind one interface handle. # C: O(N_bonds)
pub fn bond_for(iface: NetIfaceId) -> Option<Arc<BondMaster>> {
    BONDS.lock().iter().find(|r| r.iface == iface).map(|r| r.bond.clone())
}

/// Every registered bond. # C: O(N_bonds)
pub fn bonds() -> Vec<(NetIfaceId, Arc<BondMaster>)> {
    BONDS.lock().iter().map(|r| (r.iface, r.bond.clone())).collect()
}

fn insert(iface: NetIfaceId, bond: Arc<BondMaster>) { BONDS.lock().push(Row { iface, bond }); }

fn take(iface: NetIfaceId) -> Option<Arc<BondMaster>> {
    let mut g = BONDS.lock();
    let pos = g.iter().position(|r| r.iface == iface)?;
    Some(g.remove(pos).bond)
}

fn resolve(ifindex: u32) -> Option<(NetIfaceId, Arc<dyn net::netdev::NetDev>)> {
    let stack = net::global_stack();
    let ns = net::netdev::current_net_ns();
    stack.ifaces.lookup_ifindex_in_ns(ifindex, ns)
}

/// The `bond` link kind.
pub struct BondLinkKind;

/// The registration this kind publishes.
pub static BOND_LINK_KIND_OPS: BondLinkKind = BondLinkKind;

impl LinkKindOps for BondLinkKind {
    /// # C: O(1)
    fn kind(&self) -> &'static str { BOND_LINK_KIND }

    /// # C: O(N)
    fn validate(&self, msg: &LinkMsg<'_>) -> Result<(), Errno> {
        let Some(blob) = msg.data else { return Ok(()); };
        // A creation has no slaves and is administratively down, so the
        // dependency rules are checked against that state, not a live one.
        let fresh = BondMaster::new("bond");
        netlink::parse_and_check(blob, &fresh.state_view())?;
        Ok(())
    }

    /// # C: O(N_ifaces)
    fn newlink(&self, msg: &LinkMsg<'_>) -> Result<u32, Errno> {
        let name = msg.name.ok_or(Errno::Einval)?;
        let bond = Arc::new(BondMaster::new(name));
        if let Some(blob) = msg.data {
            let writes = netlink::parse_and_check(blob, &bond.state_view())?;
            apply(&bond, &writes)?;
        }
        let stack = net::global_stack();
        let ns = net::netdev::current_net_ns();
        let id = stack.ifaces.register_in_ns(bond.clone(), ns);
        insert(id, bond);
        stack.ifaces.ifindex_in_ns(id, ns).ok_or(Errno::Enodev)
    }

    /// # C: O(N_ifaces)
    fn changelink(&self, ifindex: u32, msg: &LinkMsg<'_>) -> Result<(), Errno> {
        let Some(blob) = msg.data else { return Ok(()); };
        let (id, _) = resolve(ifindex).ok_or(Errno::Enodev)?;
        let bond = bond_for(id).ok_or(Errno::Enodev)?;
        // The live state is what the dependency rules are judged against: an
        // option that needs the bond down must be refused while it is up.
        let writes = netlink::parse_and_check(blob, &bond.state_view())?;
        apply(&bond, &writes)
    }

    /// # C: O(N_ifaces)
    fn dellink(&self, ifindex: u32) -> Result<(), Errno> {
        let (id, _) = resolve(ifindex).ok_or(Errno::Enodev)?;
        let bond = take(id).ok_or(Errno::Enodev)?;
        // Slaves outlive the master and must be handed back their own identity
        // rather than left carrying the bond's address.
        for name in bond.slave_names() { let _ = bond.release(&name); }
        Ok(())
    }
}

/// The `bond` slave kind: enslaving an interface into a master.
pub struct BondSlaveKind;

/// The registration the slave side publishes.
pub static BOND_SLAVE_KIND_OPS: BondSlaveKind = BondSlaveKind;

/// Enslave `ifindex` into the bond named by `master_ifindex`.
/// # C: O(N_ifaces)
pub fn enslave(master_ifindex: u32, ifindex: u32) -> Result<(), Errno> {
    let (master_id, _) = resolve(master_ifindex).ok_or(Errno::Enodev)?;
    let bond = bond_for(master_id).ok_or(Errno::Einval)?;
    let (slave_id, dev) = resolve(ifindex).ok_or(Errno::Enodev)?;
    if slave_id == master_id { return Err(Errno::Eperm); }
    bond.enslave(dev).map(|_| ()).map_err(|_| Errno::Ebusy)
}

/// Release `ifindex` from whichever bond holds it.
/// # C: O(N_bonds · N_slaves)
pub fn release(ifindex: u32) -> Result<(), Errno> {
    let (_, dev) = resolve(ifindex).ok_or(Errno::Enodev)?;
    let name = dev.name();
    for (_, bond) in bonds() {
        if bond.release(&name).is_ok() { return Ok(()); }
    }
    Err(Errno::Einval)
}

fn apply(bond: &Arc<BondMaster>, writes: &[OptionWrite]) -> Result<(), Errno> {
    let mut params = bond.params();
    for w in writes { crate::options::apply_write(&mut params, w)?; }
    bond.set_params(params);
    Ok(())
}

/// Publish both kinds. # C: O(N_kinds)
pub fn init() -> bool {
    rtnl_link::register(&BOND_LINK_KIND_OPS).is_ok()
}
