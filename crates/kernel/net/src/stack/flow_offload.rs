//! Software flowtable ownership for nftables `flow_offload`.
//!
//! Linux keeps this outside the ordinary filter walk: a confirmed conntrack
//! entry owns two tuple keys, two route snapshots, and a pre-routing hook can
//! forward either direction without re-running the normal chains.

extern crate alloc;

use alloc::{string::String, sync::Arc, vec::Vec};
use conntrack::entry::ProtoState;
use conntrack::tuple::{InetAddr, ProtoPart, Tuple, TupleEnd};
use conntrack::uapi::{IPPROTO_TCP, IPPROTO_UDP, IPS_ASSURED, IPS_CONFIRMED,
    IPS_OFFLOAD, IPS_SEEN_REPLY, IPS_SEQ_ADJUST, NFPROTO_IPV4, NFPROTO_IPV6};

use crate::addr::{Ipv4Addr, Ipv6Addr, NetIfaceId};
use crate::netfilter_action::ApplyError;
use crate::netfilter_hook::{NF_INET_FORWARD, NF_INET_POST_ROUTING,
    NF_INET_PRE_ROUTING, NFPROTO_IPV4 as NF_V4, NFPROTO_IPV6 as NF_V6};
use crate::netdev::{NetError, NetResult};
use crate::pkt::{Pkt, TxNextHop};
use crate::stack::NetStack;

const NFPROTO_INET: u8 = 1;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum FlowRoute {
    V4 { iface: NetIfaceId, next_hop: Ipv4Addr },
    V6 { iface: NetIfaceId, next_hop: Ipv6Addr },
}

pub(crate) struct FlowEntry {
    pub(crate) conn: Arc<conntrack::Conn>,
    pub(crate) routes: [FlowRoute; 2],
}

/// A device selector on a flowtable's netdev ingress hook.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowtableDevice {
    Name(String),
    Prefix(String),
}

/// Namespace-owned nftables flowtable object and its netdev ingress hook.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowtableConfig {
    pub family: u8,
    pub table: String,
    pub name: String,
    pub hook_num: u32,
    pub priority: i32,
    pub devices: Vec<FlowtableDevice>,
    pub flags: u32,
    pub handle: u64,
}

impl NetStack {
    /// Publish one nftables flowtable configuration before rules may refer to it.
    /// # C: O(log N_flowtables)
    pub fn register_flowtable_in(&self, net_ns: u64, family: u8, table: &str, name: &str,
                                 hook_num: u32, priority: i32, devices: Vec<FlowtableDevice>, flags: u32)
                                 -> Option<u64> {
        let key = (net_ns, family, String::from(table), String::from(name));
        let mut flowtables = self.flowtables.lock();
        if flowtables.contains_key(&key) { return None; }
        let mut handle = self.next_flowtable_handle.lock();
        let assigned = *handle;
        *handle = handle.wrapping_add(1).max(1);
        flowtables.insert(key, FlowtableConfig {
            family, table: String::from(table), name: String::from(name), hook_num, priority,
            devices, flags, handle: assigned,
        });
        Some(assigned)
    }

    /// Remove a flowtable and all entries it owns. # C: O(N_flows)
    pub fn unregister_flowtable_in(&self, net_ns: u64, family: u8,
                                   nft_table: &str, name: &str) -> bool {
        let key = (net_ns, family, String::from(nft_table), String::from(name));
        let removed_config = {
            let mut flowtables = self.flowtables.lock();
            if flowtables.get(&key).is_some_and(|config| config.table == nft_table) {
                flowtables.remove(&key).is_some()
            } else { false }
        };
        let mut flows = self.flow_offload.lock();
        let mut removed = alloc::vec::Vec::new();
        for ((ns, table_name, flowtable_name, _), entry) in flows.iter() {
            if *ns == net_ns && table_name == nft_table && flowtable_name == name
                && !removed.iter().any(|old: &Arc<FlowEntry>| Arc::ptr_eq(old, entry)) {
                removed.push(Arc::clone(entry));
            }
        }
        flows.retain(|(ns, table_name, flowtable_name, _), _| *ns != net_ns
            || table_name != nft_table || flowtable_name != name);
        drop(flows);
        for entry in removed { entry.conn.clear_status_bits(IPS_OFFLOAD); }
        removed_config
    }

    fn flowtable_config(&self, net_ns: u64, family: u8, nft_table: &str, name: &str)
        -> Option<FlowtableConfig> {
        let flowtables = self.flowtables.lock();
        flowtables.get(&(net_ns, family, String::from(nft_table), String::from(name))).cloned()
            .or_else(|| (matches!(family, NF_V4 | NF_V6)).then(||
                flowtables.get(&(net_ns, NFPROTO_INET, String::from(nft_table), String::from(name)))
                    .cloned()).flatten())
    }

    fn flowtable_exists(&self, net_ns: u64, family: u8, nft_table: &str, name: &str) -> bool {
        self.flowtable_config(net_ns, family, nft_table, name).is_some()
    }

    fn flowtable_applies(&self, net_ns: u64, family: u8, nft_table: &str, name: &str,
                         iface: NetIfaceId) -> bool {
        let Some(config) = self.flowtable_config(net_ns, family, nft_table, name) else { return false; };
        !config.devices.is_empty() && config.devices.iter().any(|device| match device {
            FlowtableDevice::Name(name) => self.ifaces.lookup_name_in_ns(name, net_ns)
                .is_some_and(|(id, _)| id == iface),
            FlowtableDevice::Prefix(prefix) => self.ifaces.lookup_in_ns(iface, net_ns)
                .is_some_and(|dev| dev.name().starts_with(prefix)),
        })
    }

    /// Snapshot flowtable objects for nf_tables GET/dump serialization.
    /// # C: O(N_flowtables)
    pub fn flowtables_snapshot_in(&self, net_ns: u64, family: u8) -> Vec<FlowtableConfig> {
        self.flowtables.lock().iter()
            .filter(|((ns, fam, _, _), _)| *ns == net_ns && *fam == family)
            .map(|(_, config)| config.clone()).collect()
    }

    /// Install a bidirectional software flow after the FORWARD expression has
    /// observed a confirmed, assured conntrack entry. # C: O(routes + 1)
    pub(crate) fn offload_flow(&self, nft_table: &str, table: &str, p: &Pkt, family: u8, hook: u32)
        -> Result<(), ApplyError>
    {
        if hook != NF_INET_FORWARD || nft_table.is_empty() || table.is_empty() {
            return Err(ApplyError::Unsupported);
        }
        let Some((_ct_table, Some(conn), _info, dir)) = p.conntrack_state_owned() else {
            return Err(ApplyError::Invalid);
        };
        if !self.flowtable_exists(conn.net_ns, family, nft_table, table) {
            return Err(ApplyError::Unsupported);
        }
        let status = conn.status();
        if status & (IPS_CONFIRMED | IPS_SEEN_REPLY | IPS_ASSURED)
                != (IPS_CONFIRMED | IPS_SEEN_REPLY | IPS_ASSURED)
            || status & (IPS_OFFLOAD | IPS_SEQ_ADJUST) != 0
            || conn.helper.lock().is_some()
        { return Ok(()); }
        let tuple = conn.tuple(dir);
        if tuple.l3num != family || !matches!(tuple.protonum, IPPROTO_TCP | IPPROTO_UDP) {
            return Ok(());
        }
        if family == NF_V4 {
            let ihl = (p.data().get(0).copied().unwrap_or(0) & 0x0f) as usize * 4;
            let frag = p.data().get(6..8).map(|b| u16::from_be_bytes([b[0], b[1]]));
            if ihl != 20 || frag.is_some_and(|bits| bits & 0x3fff != 0) { return Ok(()); }
        }
        if tuple.protonum == IPPROTO_TCP {
            let Some(offset) = transport_offset(p.data(), family) else { return Ok(()); };
            let Some(flags) = p.data().get(offset + 13).copied() else { return Ok(()); };
            if flags & (crate::tcp_hdr::flags::FIN | crate::tcp_hdr::flags::RST) != 0 {
                return Ok(());
            }
            let established = match &*conn.proto.lock() {
                ProtoState::Tcp(track) => track.state
                    == conntrack::proto::tcp_state::TCP_CONNTRACK_ESTABLISHED,
                _ => false,
            };
            if !established { return Ok(()); }
        }
        let Some(current) = route_from_packet(p, family) else { return Err(ApplyError::Invalid); };
        let Some(reverse) = self.route_for_tuple(conn.net_ns, conn.tuple(dir ^ 1),
                                                  conn.mark.load(core::sync::atomic::Ordering::Acquire))
            else { return Err(ApplyError::Invalid); };
        let mut routes = [FlowRoute::V4 { iface: current_iface(current), next_hop: Ipv4Addr::ANY };
            2];
        routes[dir as usize] = current;
        routes[(dir ^ 1) as usize] = reverse;
        if conn.status.fetch_or(IPS_OFFLOAD, core::sync::atomic::Ordering::AcqRel) & IPS_OFFLOAD != 0 {
            return Ok(());
        }
        let entry = Arc::new(FlowEntry { conn: conn.clone(), routes });
        let mut flows = self.flow_offload.lock();
        flows.insert((conn.net_ns, String::from(nft_table), String::from(table), conn.orig), entry.clone());
        flows.insert((conn.net_ns, String::from(nft_table), String::from(table), conn.reply_tuple()), entry);
        drop(flows);
        Ok(())
    }

    /// Lookup and forward one packet before PRE_ROUTING. `None` means that no
    /// flow owns it and the ordinary route/filter path must continue. # C: O(N flowtables)
    pub(crate) fn flow_offload_ingress(&self, net_ns: u64, iface: NetIfaceId,
                                       l3: &[u8], family: u8)
        -> Option<NetResult<()>>
    {
        let tuple = flow_tuple(l3, family)?;
        let mut flows = self.flow_offload.lock();
        let found = flows.iter()
            .find(|((ns, nft_table, table, key), _)| *ns == net_ns && *key == tuple
                && self.flowtable_applies(net_ns, family, nft_table, table, iface))
            .map(|(_, entry)| Arc::clone(entry));
        let entry = found?;
        let now = crate::stack::net_now_ns() / 1_000_000_000;
        if entry.conn.dying() || entry.conn.expired(now)
            || entry.conn.status() & IPS_OFFLOAD == 0
        {
            flows.retain(|_, candidate| !Arc::ptr_eq(candidate, &entry));
            entry.conn.clear_status_bits(IPS_OFFLOAD);
            return None;
        }
        drop(flows);
        let dir: u8 = if entry.conn.orig == tuple { 0 } else { 1 };
        let route = entry.routes[dir as usize];
        if self.route_for_tuple(net_ns, tuple, entry.conn.mark.load(
            core::sync::atomic::Ordering::Acquire)) != Some(route) {
            let mut flows = self.flow_offload.lock();
            flows.retain(|_, candidate| !Arc::ptr_eq(candidate, &entry));
            entry.conn.clear_status_bits(IPS_OFFLOAD);
            return None;
        }
        Some(self.forward_offloaded(net_ns, l3, family, &entry, dir, route))
    }

    fn forward_offloaded(&self, net_ns: u64, l3: &[u8], family: u8,
                          entry: &FlowEntry, dir: u8, route: FlowRoute) -> NetResult<()> {
        let total = match family {
            NF_V4 => {
                if l3.len() < 20 || l3[0] >> 4 != 4 { return Ok(()); }
                let ihl = (l3[0] & 0x0f) as usize * 4;
                let total = u16::from_be_bytes([l3[2], l3[3]]) as usize;
                if ihl < 20 || total < ihl || total > l3.len() { return Ok(()); }
                total
            }
            NF_V6 => {
                if l3.len() < 40 || l3[0] >> 4 != 6 { return Ok(()); }
                let total = 40 + u16::from_be_bytes([l3[4], l3[5]]) as usize;
                if total > l3.len() { return Ok(()); }
                total
            }
            _ => return Ok(()),
        };
        let mut p = Pkt::from_owned(l3[..total].to_vec());
        let table = self.conntrack_in(net_ns);
        p.set_conntrack_state(table, Some(entry.conn.clone()), entry.conn.ctinfo(dir), dir);
        p.tx.mark = entry.conn.mark.load(core::sync::atomic::Ordering::Acquire);
        p.iface = Some(route_iface(route));
        match route {
            FlowRoute::V4 { next_hop, .. } => {
                if p.data().get(8).copied().unwrap_or(0) <= 1 { return Ok(()); }
                crate::netfilter_action::apply_conntrack_packet(
                    &mut p, entry.conn.clone(), dir, family, NF_INET_PRE_ROUTING)
                    .map_err(|_| NetError::Einval)?;
                let b = p.data_mut();
                b[8] -= 1;
                b[10] = 0; b[11] = 0;
                let csum = crate::ipv4::ip_checksum(&b[..((b[0] & 0x0f) as usize * 4)]);
                b[10..12].copy_from_slice(&csum.to_be_bytes());
                crate::netfilter_action::apply_conntrack_packet(
                    &mut p, entry.conn.clone(), dir, family, NF_INET_POST_ROUTING)
                    .map_err(|_| NetError::Einval)?;
                p.next_hop = Some(TxNextHop::V4(next_hop));
            }
            FlowRoute::V6 { next_hop, .. } => {
                if p.data().get(7).copied().unwrap_or(0) <= 1 { return Ok(()); }
                crate::netfilter_action::apply_conntrack_packet(
                    &mut p, entry.conn.clone(), dir, family, NF_INET_PRE_ROUTING)
                    .map_err(|_| NetError::Einval)?;
                p.data_mut()[7] -= 1;
                crate::netfilter_action::apply_conntrack_packet(
                    &mut p, entry.conn.clone(), dir, family, NF_INET_POST_ROUTING)
                    .map_err(|_| NetError::Einval)?;
                p.next_hop = Some(TxNextHop::V6 { addr: next_hop, src: Ipv6Addr::ANY });
            }
        }
        entry.conn.counters[dir as usize].account(total as u64);
        self.ifaces.acquire_egress_in_ns(route_iface(route), net_ns)
            .ok_or(NetError::Enetunreach)?.xmit(p)
    }

    fn route_for_tuple(&self, net_ns: u64, tuple: Tuple, mark: u32) -> Option<FlowRoute> {
        match tuple.dst.addr {
            InetAddr(bytes) if tuple.l3num == NFPROTO_IPV4 => {
                let dst = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                let route = self.routes.lookup_result_mark_in(net_ns, dst, mark).ok()?;
                Some(FlowRoute::V4 { iface: route.iface,
                    next_hop: crate::route::RouteRecord::next_hop_for(route.gateway, dst) })
            }
            InetAddr(bytes) if tuple.l3num == NFPROTO_IPV6 => {
                let dst = Ipv6Addr(bytes);
                let route = self.routes6.lookup_policy_mark_in(net_ns, dst,
                    self.policy_rules(), mark)?;
                Some(FlowRoute::V6 { iface: route.iface,
                    next_hop: crate::route6::next_hop6_for(route.gateway, dst) })
            }
            _ => None,
        }
    }
}

fn current_iface(route: FlowRoute) -> NetIfaceId { route_iface(route) }
fn route_iface(route: FlowRoute) -> NetIfaceId {
    match route { FlowRoute::V4 { iface, .. } | FlowRoute::V6 { iface, .. } => iface }
}

fn route_from_packet(p: &Pkt, family: u8) -> Option<FlowRoute> {
    let iface = p.iface?;
    match (family, p.next_hop?) {
        (NF_V4, TxNextHop::V4(next_hop)) => Some(FlowRoute::V4 { iface, next_hop }),
        (NF_V6, TxNextHop::V6 { addr: next_hop, .. }) => Some(FlowRoute::V6 { iface, next_hop }),
        _ => None,
    }
}

pub(crate) fn flow_tuple(pkt: &[u8], family: u8) -> Option<Tuple> {
    let (src, dst, proto, off) = match family {
        NF_V4 => {
            if pkt.len() < 20 || pkt[0] >> 4 != 4 { return None; }
            let ihl = (pkt[0] & 0x0f) as usize * 4;
            if ihl < 20 || ihl > pkt.len() { return None; }
            let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
            if frag & 0x3fff != 0 { return None; }
            (InetAddr::v4(pkt[12..16].try_into().ok()?),
             InetAddr::v4(pkt[16..20].try_into().ok()?), pkt[9], ihl)
        }
        NF_V6 => {
            if pkt.len() < 40 || pkt[0] >> 4 != 6 { return None; }
            let (proto, off) = match crate::ipv6_ext::walk(pkt[6], &pkt[40..]).ok()? {
                crate::ipv6_ext::ExtWalk::Done { next_header, payload } =>
                    (next_header, pkt.len() - payload.len()),
                crate::ipv6_ext::ExtWalk::Fragment { next_header, offset: 0, payload, .. } =>
                    (next_header, pkt.len() - payload.len()),
                crate::ipv6_ext::ExtWalk::Fragment { .. } => return None,
            };
            (InetAddr::v6(pkt[8..24].try_into().ok()?),
             InetAddr::v6(pkt[24..40].try_into().ok()?), proto, off)
        }
        _ => return None,
    };
    let l4 = pkt.get(off..)?;
    if l4.len() < 4 || !matches!(proto, IPPROTO_TCP | IPPROTO_UDP) { return None; }
    Some(Tuple { src: TupleEnd { addr: src, proto: ProtoPart::port(
        u16::from_be_bytes([l4[0], l4[1]])) },
        dst: TupleEnd { addr: dst, proto: ProtoPart::port(
            u16::from_be_bytes([l4[2], l4[3]])) }, l3num: family, protonum: proto, zone: 0 })
}

fn transport_offset(pkt: &[u8], family: u8) -> Option<usize> {
    match family {
        NF_V4 => {
            if pkt.len() < 20 || pkt[0] >> 4 != 4 { return None; }
            let ihl = (pkt[0] & 0x0f) as usize * 4;
            (ihl >= 20 && ihl <= pkt.len()).then_some(ihl)
        }
        NF_V6 => match crate::ipv6_ext::walk(pkt.get(6).copied()?, pkt.get(40..)?).ok()? {
            crate::ipv6_ext::ExtWalk::Done { payload, .. }
            | crate::ipv6_ext::ExtWalk::Fragment { offset: 0, payload, .. } =>
                Some(pkt.len() - payload.len()),
            crate::ipv6_ext::ExtWalk::Fragment { .. } => None,
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tuple_parser_uses_wire_addresses_and_ports() {
        let mut packet = [0u8; 28];
        packet[0] = 0x45;
        packet[9] = IPPROTO_UDP;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&5353u16.to_be_bytes());
        let tuple = flow_tuple(&packet, NFPROTO_IPV4).expect("flow tuple");
        assert_eq!(tuple.src.addr, InetAddr::v4([10, 0, 0, 1]));
        assert_eq!(tuple.dst.addr, InetAddr::v4([10, 0, 0, 2]));
        assert_eq!(tuple.src.proto.port, 1234);
        assert_eq!(tuple.dst.proto.port, 5353);
    }

    #[test]
    fn flowtable_registration_is_namespace_scoped_and_dumpable() {
        let stack = NetStack::new();
        let handle = stack.register_flowtable_in(7, 2, "filter", "ft", 0, -256,
            alloc::vec![FlowtableDevice::Name(String::from("eth0"))], 0).expect("first registration");
        assert!(stack.register_flowtable_in(7, 2, "filter", "ft", 0, -256,
            alloc::vec![FlowtableDevice::Name(String::from("eth0"))], 0).is_none());
        assert!(stack.register_flowtable_in(7, 2, "nat", "ft", 0, -256,
            alloc::vec![FlowtableDevice::Name(String::from("eth0"))], 0).is_some());
        let snapshot = stack.flowtables_snapshot_in(7, 2);
        assert_eq!(snapshot.len(), 2);
        let filter = snapshot.iter().find(|config| config.table == "filter").unwrap();
        assert_eq!((filter.table.as_str(), filter.name.as_str(),
            filter.hook_num, filter.priority, filter.handle),
            ("filter", "ft", 0, -256, handle));
        assert!(stack.unregister_flowtable_in(7, 2, "filter", "ft"));
        assert_eq!(stack.flowtables_snapshot_in(7, 2).len(), 1);
    }
}
