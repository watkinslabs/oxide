//! The `vlan` entry in the rtnetlink link-kind table. Creation is the same
//! decision `netlink.rs` already makes; this module supplies only the
//! lower-device resolution and the registration, so `ip link add link eth0
//! name eth0.100 type vlan id 100` reaches code that was otherwise unreachable.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;

use net::addr::NetIfaceId;
use net::netdev::NetDev;
use rtnl_link::{LinkKindOps, LinkMsg};
use syscall::errno::Errno;

use crate::caps::RealDevCaps;
use crate::dev::VlanDev;
use crate::netlink::{self, LinkAttrs};
use crate::registry::table;
use crate::uapi::VLAN_LINK_KIND;

/// Resolve a lower interface index to the handle, device and properties that
/// creation needs. # C: O(N_ifaces)
fn resolve_dev(ifindex: u32) -> Option<(NetIfaceId, Arc<dyn NetDev>, RealDevCaps)> {
    let stack = net::global_stack();
    let ns = net::netdev::current_net_ns();
    let (id, dev) = stack.ifaces.lookup_ifindex_in_ns(ifindex, ns)?;
    let caps = RealDevCaps::from_netdev(dev.as_ref());
    Some((id, dev, caps))
}

/// Resolve a namespace id to the reference the registry publishes into.
/// # C: O(N_namespaces)
fn owner_of(ns: u64) -> Option<network_namespace::NetworkNamespaceRef> {
    if ns == 0 { Some(network_namespace::initial()) }
    else { network_namespace::lookup_u64(ns) }
}

/// The `vlan` link kind.
pub struct VlanLinkKind;

/// The registration this kind publishes.
pub static VLAN_LINK_KIND_OPS: VlanLinkKind = VlanLinkKind;

impl LinkKindOps for VlanLinkKind {
    /// # C: O(1)
    fn kind(&self) -> &'static str { VLAN_LINK_KIND }

    /// A VLAN interface is defined by the interface whose frames it tags, so a
    /// request naming none cannot be completed. # C: O(1)
    fn needs_lower(&self) -> bool { true }

    /// # C: O(N)
    fn validate(&self, msg: &LinkMsg<'_>) -> Result<(), Errno> {
        let link = link_attrs(msg);
        let data = msg.data.map(netlink::parse).transpose()?;
        netlink::validate(&link, data.as_ref())
    }

    /// # C: O(N_ifaces)
    fn newlink(&self, msg: &LinkMsg<'_>) -> Result<u32, Errno> {
        let link = link_attrs(msg);
        let Some(blob) = msg.data else { return Err(Errno::Einval) };
        let data = netlink::parse(blob)?;
        netlink::validate(&link, Some(&data))?;
        let name = msg.name.ok_or(Errno::Einval)?;
        let req = netlink::newlink(&link, &data, table(),
            |ifindex| resolve_dev(ifindex).map(|(id, _, caps)| (id, caps)))?;
        let Some((_, real, _)) = link.link.and_then(resolve_dev) else {
            return Err(Errno::Enodev);
        };
        install(&req, name, real)
    }

    /// # C: O(N_ifaces)
    fn changelink(&self, ifindex: u32, msg: &LinkMsg<'_>) -> Result<(), Errno> {
        let Some(blob) = msg.data else { return Ok(()); };
        let data = netlink::parse(blob)?;
        let dev = lookup_vlan(ifindex).ok_or(Errno::Enodev)?;
        netlink::changelink(&dev, &data)
    }

    /// # C: O(N_ifaces)
    fn dellink(&self, ifindex: u32) -> Result<(), Errno> {
        let stack = net::global_stack();
        let ns = net::netdev::current_net_ns();
        let (id, _) = stack.ifaces.lookup_ifindex_in_ns(ifindex, ns).ok_or(Errno::Enodev)?;
        // The tag index is released first: a claimed tag whose interface is
        // being torn down would demultiplex frames into a dying device.
        table().remove(id).ok_or(Errno::Enodev)?;
        Ok(())
    }
}

fn link_attrs<'a>(msg: &LinkMsg<'a>) -> LinkAttrs<'a> {
    LinkAttrs { address: msg.address, mtu: msg.mtu, link: msg.link }
}

fn lookup_vlan(ifindex: u32) -> Option<Arc<VlanDev>> {
    let stack = net::global_stack();
    let ns = net::netdev::current_net_ns();
    let (id, _) = stack.ifaces.lookup_ifindex_in_ns(ifindex, ns)?;
    table().by_iface(id)
}

/// Build the interface, claim its tag, then publish it. The tag is claimed
/// before publication so a duplicate loses without a half-built interface ever
/// appearing in the registry.
/// # C: O(N_ifaces)
fn install(req: &netlink::CreateRequest, name: &str, real: Arc<dyn NetDev>)
    -> Result<u32, Errno>
{
    let stack = net::global_stack();
    let ns = net::netdev::current_net_ns();
    let owner = owner_of(ns).ok_or(Errno::Enodev)?;
    if stack.ifaces.lookup_name_in_ns(name, ns).is_some() { return Err(Errno::Eexist); }

    let dev = Arc::new(VlanDev::new(String::from(name), req.vlan_id, req.proto,
                                    req.real, real, req.caps, req.mac));
    dev.set_mtu(req.mtu).map_err(|_| Errno::Einval)?;
    dev.set_flags(req.flags);
    dev.with_maps(|m| {
        for e in &req.ingress { m.set_ingress(e.to, e.from); }
        for e in &req.egress { m.set_egress(e.from, e.to); }
    });

    // Prepared, then indexed, then published. The tag index is written while
    // the generation is still hidden, so a frame can never reach an interface
    // whose tag has not been claimed, and a duplicate tag aborts the
    // registration instead of leaving a half-built interface behind.
    let reg = stack.prepare_iface(dev.clone(), &owner).ok_or(Errno::Enodev)?;
    let id = reg.id();
    if table().insert(id, dev).is_err() {
        stack.abort_iface(reg);
        return Err(Errno::Eexist);
    }
    if !stack.publish_iface(reg) {
        table().remove(id);
        return Err(Errno::Enodev);
    }
    stack.ifaces.ifindex_in_ns(id, ns).ok_or(Errno::Enodev)
}

/// Publish the kind. Called once during network initialisation; a second call
/// is refused by the registry rather than shadowing the first.
/// # C: O(N_kinds)
pub fn init() -> bool { rtnl_link::register(&VLAN_LINK_KIND_OPS).is_ok() }
