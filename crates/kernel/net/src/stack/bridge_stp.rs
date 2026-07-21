//! Canonical IEEE 802.1D bridge root, port-role, and timer state.

use super::bridge::{Bridge, BridgePort, BridgeTable, BR_STATE_FORWARDING};
use super::bridge_stp_bpdu::{is_tcn_bpdu, tcn_bpdu, StpConfigBpdu};
use super::*;

const BR_STATE_LISTENING: u8 = 1;
const BR_STATE_LEARNING: u8 = 2;
const BR_STATE_BLOCKING: u8 = 4;
const STP_DEST: crate::MacAddr = crate::MacAddr([1, 0x80, 0xc2, 0, 0, 0]);
const LLC_LEN: usize = 3;
const LLC: [u8; LLC_LEN] = [0x42, 0x42, 0x03];

pub(super) struct BridgeStp {
    pub(super) enabled: bool,
    pub(super) root_id: [u8; 8],
    pub(super) root_path_cost: u32,
    pub(super) root_port: Option<NetIfaceId>,
    pub(super) topology_change: bool,
    pub(super) topology_change_detected: bool,
    topology_change_until_ns: u64,
    tcn_deadline_ns: u64,
    hello_deadline_ns: u64,
}

pub(super) struct StpPort {
    pub(super) state: u8,
    pub(super) designated_root: [u8; 8],
    pub(super) designated_cost: u32,
    pub(super) designated_bridge: [u8; 8],
    pub(super) designated_port: u16,
    received: Option<ReceivedBpdu>,
    transition_deadline_ns: u64,
    topology_change_ack: bool,
}

struct ReceivedBpdu { bpdu: StpConfigBpdu, received_ns: u64, expires_ns: u64 }

pub(super) struct StpTx { pub(super) port: NetIfaceId, pub(super) net_ns: u64, pub(super) frame: Vec<u8> }

impl BridgeStp {
    pub(super) fn new(id: [u8; 8]) -> Self {
        Self { enabled: false, root_id: id, root_path_cost: 0, root_port: None,
            topology_change: false, topology_change_detected: false, topology_change_until_ns: 0,
            tcn_deadline_ns: 0, hello_deadline_ns: 0 }
    }
}

impl StpPort {
    pub(super) fn new(id: [u8; 8], port_id: u16) -> Self {
        Self { state: BR_STATE_FORWARDING, designated_root: id, designated_cost: 0,
            designated_bridge: id, designated_port: port_id, received: None,
            transition_deadline_ns: 0, topology_change_ack: false }
    }
}

impl BridgeTable {
    pub(crate) fn stp_enable(&self, bridge: NetIfaceId, net_ns: u64) -> NetResult<()> {
        let mut state = self.state.lock();
        let row = state.get_mut(&bridge).ok_or(NetError::Enodev)?;
        if row.net_ns != net_ns || row.deleting { return Err(NetError::Enodev); }
        let now = super::monotonic_ns_safe();
        enable(row, now);
        Ok(())
    }

    pub(crate) fn stp_disable(&self, bridge: NetIfaceId, net_ns: u64) -> NetResult<()> {
        let mut state = self.state.lock();
        let row = state.get_mut(&bridge).ok_or(NetError::Enodev)?;
        if row.net_ns != net_ns || row.deleting { return Err(NetError::Enodev); }
        disable(row);
        Ok(())
    }

    pub(crate) fn stp_bpdu_ingress(&self, lease: &crate::IngressLease, header: crate::ethernet::EthHdr,
                                   frame: &[u8]) -> bool
    {
        if header.dst != STP_DEST { return false; }
        let payload = &frame[header.hdr_len..];
        if payload.len() < LLC_LEN || payload[..LLC_LEN] != LLC { return false; }
        let wire = &payload[LLC_LEN..];
        if is_tcn_bpdu(wire) {
            let mut state = self.state.lock();
            let Some(row) = state.values_mut().find(|row| row.net_ns == lease.net_ns() && row.ports.contains_key(&lease.iface())) else { return false; };
            if !row.stp.enabled { return false; }
            let own = bridge_id(row);
            if row.stp.root_port != Some(lease.iface()) {
                if let Some(port) = row.ports.get_mut(&lease.iface()) {
                    if (port.stp.designated_root, port.stp.designated_cost, port.stp.designated_bridge, port.stp.designated_port)
                    == (row.stp.root_id, row.stp.root_path_cost, own, port_id(port)) {
                        port.stp.topology_change_ack = true;
                        topology_change_detection(row, super::monotonic_ns_safe());
                        row.stp.hello_deadline_ns = super::monotonic_ns_safe();
                    }
                }
            }
            return true;
        }
        let Some(bpdu) = StpConfigBpdu::parse(wire) else { return false; };
        if bpdu.message_age >= bpdu.max_age { return true; }
        let mut state = self.state.lock();
        let Some(row) = state.values_mut().find(|row|
            row.net_ns == lease.net_ns() && row.ports.contains_key(&lease.iface())) else { return false; };
        if !row.stp.enabled { return false; }
        let now = super::monotonic_ns_safe();
        let expiry = now.saturating_add(bpdu.max_age.saturating_sub(bpdu.message_age).saturating_mul(super::bridge::CLK_TCK_NS));
        if row.ports.contains_key(&lease.iface()) {
            row.ports.get_mut(&lease.iface()).unwrap().stp.received = Some(ReceivedBpdu { bpdu, received_ns: now, expires_ns: expiry });
            recompute(row, now);
            if row.stp.root_port == Some(lease.iface()) {
                let bpdu = row.ports.get(&lease.iface()).and_then(|port| port.stp.received.as_ref()).unwrap().bpdu.clone();
                row.max_age = bpdu.max_age;
                row.hello_time = bpdu.hello_time;
                row.forward_delay = bpdu.forward_delay;
                set_topology_change(row, bpdu.topology_change, now);
                if bpdu.topology_change_ack { topology_change_acknowledged(row); }
            }
        }
        true
    }

    pub(crate) fn stp_tick(&self, now: u64) -> Vec<StpTx> {
        let mut state = self.state.lock();
        let mut tx = Vec::new();
        for row in state.values_mut() {
            if !row.stp.enabled || row.deleting { continue; }
            let expired = row.ports.values().any(|port| port.stp.received.as_ref().is_some_and(|rx| now >= rx.expires_ns));
            for port in row.ports.values_mut() {
                if port.stp.received.as_ref().is_some_and(|rx| now >= rx.expires_ns) { port.stp.received = None; }
            }
            if expired { recompute(row, now); }
            for port in row.ports.values_mut() {
                if port.stp.transition_deadline_ns != 0 && now >= port.stp.transition_deadline_ns {
                    match port.stp.state {
                        BR_STATE_LISTENING => { port.stp.state = BR_STATE_LEARNING; port.stp.transition_deadline_ns = now.saturating_add(row.forward_delay.saturating_mul(super::bridge::CLK_TCK_NS)); }
                        BR_STATE_LEARNING => { port.stp.state = BR_STATE_FORWARDING; port.stp.transition_deadline_ns = 0; }
                        _ => {}
                    }
                }
            }
            if row.stp.topology_change && now >= row.stp.topology_change_until_ns {
                set_topology_change(row, false, now);
            }
            if now >= row.stp.hello_deadline_ns {
                for (&iface, port) in &row.ports {
                    if row.stp.root_port != Some(iface) && is_designated_port(row, port) {
                        tx.push(StpTx { port: iface, net_ns: row.net_ns, frame: config_frame(row, port, now) });
                    }
                }
                for port in row.ports.values_mut() { port.stp.topology_change_ack = false; }
                row.stp.hello_deadline_ns = now.saturating_add(row.hello_time.saturating_mul(super::bridge::CLK_TCK_NS));
            }
            if row.stp.topology_change_detected && row.stp.root_port.is_some() && now >= row.stp.tcn_deadline_ns {
                let port = row.stp.root_port.unwrap();
                tx.push(StpTx { port, net_ns: row.net_ns, frame: tcn_frame(row.mac) });
                row.stp.tcn_deadline_ns = now.saturating_add(row.hello_time.saturating_mul(super::bridge::CLK_TCK_NS));
            }
        }
        tx
    }
}

impl NetStack {
    /// Advance bridge STP timers and emit due Configuration BPDUs. # C: O(N bridges + N ports + frame)
    pub fn bridge_stp_tick(&self, now: u64) {
        for tx in self.bridges.stp_tick(now) {
            if let Some(egress) = self.ifaces.acquire_egress_in_ns(tx.port, tx.net_ns) { let _ = egress.xmit_raw(&tx.frame); }
        }
    }
}

fn enable(row: &mut Bridge, now: u64) {
    row.stp.enabled = true;
    row.stp.topology_change = false;
    row.stp.topology_change_detected = false;
    row.stp.topology_change_until_ns = 0;
    row.stp.tcn_deadline_ns = 0;
    row.max_age = row.bridge_max_age;
    row.hello_time = row.bridge_hello_time;
    row.forward_delay = row.bridge_forward_delay;
    row.ageing_ns = row.bridge_ageing_ns;
    row.stp.hello_deadline_ns = now;
    for port in row.ports.values_mut() { port.stp.received = None; }
    recompute(row, now);
}

fn disable(row: &mut Bridge) {
    row.stp.enabled = false;
    let id = bridge_id(row);
    row.stp.root_id = id;
    row.stp.root_path_cost = 0;
    row.stp.root_port = None;
    row.stp.topology_change = false;
    row.stp.topology_change_detected = false;
    row.stp.topology_change_until_ns = 0;
    row.stp.tcn_deadline_ns = 0;
    row.max_age = row.bridge_max_age;
    row.hello_time = row.bridge_hello_time;
    row.forward_delay = row.bridge_forward_delay;
    row.ageing_ns = row.bridge_ageing_ns;
    for port in row.ports.values_mut() {
        port.stp.received = None;
        port.stp.state = BR_STATE_FORWARDING;
        port.stp.transition_deadline_ns = 0;
        let port_id = port_id(port);
        set_designated_values(port, id, 0, id, port_id);
    }
}

pub(super) fn recompute(row: &mut Bridge, now: u64) {
    let own = bridge_id(row);
    let mut selected = (own, 0, own, 0, None);
    for (&iface, port) in &row.ports {
        let Some(rx) = &port.stp.received else { continue; };
        let candidate = (rx.bpdu.root_id, rx.bpdu.root_path_cost.saturating_add(port.path_cost),
            rx.bpdu.bridge_id, rx.bpdu.port_id, Some(iface));
        if candidate.0 < selected.0 || (candidate.0 == selected.0 && candidate.1 < selected.1) ||
            (candidate.0 == selected.0 && candidate.1 == selected.1 && candidate.2 < selected.2) ||
            (candidate.0 == selected.0 && candidate.1 == selected.1 && candidate.2 == selected.2 && candidate.3 < selected.3) { selected = candidate; }
    }
    let changed = row.stp.root_id != selected.0 || row.stp.root_path_cost != selected.1 || row.stp.root_port != selected.4;
    row.stp.root_id = selected.0;
    row.stp.root_path_cost = selected.1;
    row.stp.root_port = selected.4;
    if changed {
        if row.stp.root_port.is_none() {
            row.max_age = row.bridge_max_age;
            row.hello_time = row.bridge_hello_time;
            row.forward_delay = row.bridge_forward_delay;
        }
        topology_change_detection(row, now);
    }
    let advertised = (row.stp.root_id, row.stp.root_path_cost, own);
    for (&iface, port) in &mut row.ports {
        let root = Some(iface) == row.stp.root_port;
        let superior = port.stp.received.as_ref().is_some_and(|rx| {
            let theirs = (rx.bpdu.root_id, rx.bpdu.root_path_cost, rx.bpdu.bridge_id, rx.bpdu.port_id);
            theirs < (advertised.0, advertised.1, advertised.2, port_id(port))
        });
        if root || !superior { transition(port, row.forward_delay, now); set_designated_values(port, advertised.0, advertised.1, own, port_id(port)); }
        else { port.stp.state = BR_STATE_BLOCKING; port.stp.transition_deadline_ns = 0; }
    }
}

fn transition(port: &mut BridgePort, forward_delay: u64, now: u64) {
    if port.stp.state == BR_STATE_BLOCKING || port.stp.state == BR_STATE_FORWARDING {
        port.stp.state = BR_STATE_LISTENING;
        port.stp.transition_deadline_ns = now.saturating_add(forward_delay.saturating_mul(super::bridge::CLK_TCK_NS));
    }
}

fn is_designated_port(row: &Bridge, port: &BridgePort) -> bool {
    (port.stp.designated_root, port.stp.designated_cost, port.stp.designated_bridge, port.stp.designated_port)
        == (row.stp.root_id, row.stp.root_path_cost, bridge_id(row), port_id(port))
}

fn set_topology_change(row: &mut Bridge, value: bool, now: u64) {
    if row.stp.topology_change == value { return; }
    row.stp.topology_change = value;
    row.ageing_ns = if value { row.forward_delay.saturating_mul(super::bridge::CLK_TCK_NS).saturating_mul(2) }
        else { row.bridge_ageing_ns };
    row.stp.topology_change_until_ns = if value {
        now.saturating_add(row.forward_delay.saturating_add(row.max_age).saturating_mul(super::bridge::CLK_TCK_NS))
    } else { 0 };
}

fn topology_change_detection(row: &mut Bridge, now: u64) {
    if row.stp.root_port.is_none() { set_topology_change(row, true, now); }
    else if !row.stp.topology_change_detected { row.stp.tcn_deadline_ns = now; }
    row.stp.topology_change_detected = true;
}

fn topology_change_acknowledged(row: &mut Bridge) {
    row.stp.topology_change_detected = false;
    row.stp.tcn_deadline_ns = 0;
}

fn config_frame(row: &Bridge, port: &BridgePort, now: u64) -> Vec<u8> {
    let elapsed = port.stp.received.as_ref().map_or(0, |rx| now.saturating_sub(rx.received_ns) / super::bridge::CLK_TCK_NS);
    let message_age = port.stp.received.as_ref().map_or(0, |rx| rx.bpdu.message_age.saturating_add(elapsed));
    let bpdu = StpConfigBpdu { topology_change: row.stp.topology_change, topology_change_ack: port.stp.topology_change_ack,
        root_id: row.stp.root_id, root_path_cost: row.stp.root_path_cost, bridge_id: bridge_id(row),
        port_id: port_id(port), message_age, max_age: row.max_age, hello_time: row.hello_time,
        forward_delay: row.forward_delay };
    let payload = bpdu.encode();
    let mut frame = alloc::vec![0; crate::ethernet::ETH_HDR_LEN + LLC_LEN + payload.len()];
    crate::ethernet::EthHdr::write_to(STP_DEST, row.mac, (LLC_LEN + payload.len()) as u16, &mut frame);
    frame[crate::ethernet::ETH_HDR_LEN..crate::ethernet::ETH_HDR_LEN + LLC_LEN].copy_from_slice(&LLC);
    frame[crate::ethernet::ETH_HDR_LEN + LLC_LEN..].copy_from_slice(&payload);
    frame
}

fn tcn_frame(src: crate::MacAddr) -> Vec<u8> {
    let payload = tcn_bpdu();
    let mut frame = alloc::vec![0; crate::ethernet::ETH_HDR_LEN + LLC_LEN + payload.len()];
    crate::ethernet::EthHdr::write_to(STP_DEST, src, (LLC_LEN + payload.len()) as u16, &mut frame);
    frame[crate::ethernet::ETH_HDR_LEN..crate::ethernet::ETH_HDR_LEN + LLC_LEN].copy_from_slice(&LLC);
    frame[crate::ethernet::ETH_HDR_LEN + LLC_LEN..].copy_from_slice(&payload);
    frame
}

fn bridge_id(row: &Bridge) -> [u8; 8] { let mut id = [0; 8]; id[..2].copy_from_slice(&row.priority.to_be_bytes()); id[2..].copy_from_slice(&row.mac.0); id }
fn port_id(port: &BridgePort) -> u16 { ((port.priority as u16) << super::bridge::BR_PORT_BITS) | port.number }
fn set_designated_values(port: &mut BridgePort, root: [u8; 8], cost: u32, bridge: [u8; 8], number: u16) { port.stp.designated_root = root; port.stp.designated_cost = cost; port.stp.designated_bridge = bridge; port.stp.designated_port = number; }

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use std::sync::Mutex;

    struct Capture { mac: crate::MacAddr, frames: Mutex<Vec<Vec<u8>>> }
    impl Capture { fn new(mac: crate::MacAddr) -> Self { Self { mac, frames: Mutex::new(Vec::new()) } } }
    impl crate::NetDev for Capture {
        fn name(&self) -> &str { "stp-test" }
        fn mac(&self) -> crate::MacAddr { self.mac }
        fn mtu(&self) -> u32 { 1500 }
        fn xmit(&self, packet: crate::Pkt) -> NetResult<()> { self.frames.lock().unwrap().push(packet.data().to_vec()); Ok(()) }
        fn xmit_raw(&self, frame: &[u8]) -> NetResult<()> { self.frames.lock().unwrap().push(frame.to_vec()); Ok(()) }
        fn retire_namespace(&self) {}
        fn namespace_drop_action(&self) -> crate::NamespaceDropAction { crate::NamespaceDropAction::Destroy }
    }

    fn ethernet(dst: crate::MacAddr, src: crate::MacAddr) -> Vec<u8> {
        let mut frame = alloc::vec![0; crate::ethernet::ETH_HDR_LEN + 1];
        crate::ethernet::EthHdr::write_to(dst, src, crate::eth_p::ARP, &mut frame);
        frame
    }

    fn stp_wire(src: crate::MacAddr, bpdu: &[u8]) -> Vec<u8> {
        let mut wire = alloc::vec![0; crate::ethernet::ETH_HDR_LEN + LLC_LEN + bpdu.len()];
        crate::ethernet::EthHdr::write_to(STP_DEST, src, (LLC_LEN + bpdu.len()) as u16, &mut wire);
        wire[crate::ethernet::ETH_HDR_LEN..crate::ethernet::ETH_HDR_LEN + LLC_LEN].copy_from_slice(&LLC);
        wire[crate::ethernet::ETH_HDR_LEN + LLC_LEN..].copy_from_slice(bpdu);
        wire
    }

    #[test]
    fn enabled_stp_emits_bpdus_gates_data_and_selects_a_superior_root() {
        let stack = NetStack::new();
        let owner = crate::net_ns::test_support::allocate_namespace();
        let bridge_dev = Arc::new(Capture::new(crate::MacAddr([2, 0, 0, 0, 9, 1])));
        let first = Arc::new(Capture::new(crate::MacAddr([2, 0, 0, 0, 9, 2])));
        let second = Arc::new(Capture::new(crate::MacAddr([2, 0, 0, 0, 9, 3])));
        let ns = owner.id().as_u64();
        let bridge = stack.ifaces.register_in_ns(bridge_dev.clone(), ns);
        let first_id = stack.ifaces.register_in_ns(first.clone(), ns);
        let second_id = stack.ifaces.register_in_ns(second.clone(), ns);
        let rtnl = stack.rtnl_lock();
        stack.bridge_create_in_rtnl(&rtnl, bridge, ns, bridge_dev.mac()).unwrap();
        stack.bridge_add_port_in_rtnl(&rtnl, bridge, first_id).unwrap();
        stack.bridge_add_port_in_rtnl(&rtnl, bridge, second_id).unwrap();
        drop(rtnl);
        stack.bridge_set_timing(ns, bridge, super::super::BridgeTiming::ForwardDelay, 1).unwrap();
        stack.bridge_enable_stp(ns, bridge).unwrap();
        assert_eq!(stack.bridge_info(ns, bridge).unwrap().stp_enabled, 1);
        assert_eq!(stack.bridge_port_info(ns, bridge, 1).unwrap().state, BR_STATE_LISTENING);
        assert_eq!(first.frames.lock().unwrap()[0][..6], STP_DEST.0);
        first.frames.lock().unwrap().clear(); second.frames.lock().unwrap().clear();
        let data = ethernet(crate::MacAddr::BROADCAST, crate::MacAddr([2, 0, 0, 0, 9, 9]));
        stack.deliver_ethernet(first_id, &data).unwrap();
        assert!(second.frames.lock().unwrap().is_empty());
        let now = super::super::monotonic_ns_safe().saturating_add(30_000_000);
        stack.bridge_stp_tick(now); stack.bridge_stp_tick(now.saturating_add(20_000_000));
        second.frames.lock().unwrap().clear();
        stack.deliver_ethernet(first_id, &data).unwrap();
        assert_eq!(*second.frames.lock().unwrap(), alloc::vec![data.clone()]);
        let bpdu = StpConfigBpdu { topology_change: false, topology_change_ack: false,
            root_id: [0x70, 0, 0, 0, 0, 0, 0, 1], root_path_cost: 0,
            bridge_id: [0x70, 0, 0, 0, 0, 0, 0, 2], port_id: 0x8001,
            message_age: 0, max_age: 2_000, hello_time: 200, forward_delay: 1_500 };
        let body = bpdu.encode();
        let wire = stp_wire(crate::MacAddr([2, 0, 0, 0, 9, 8]), &body);
        stack.deliver_ethernet(first_id, &wire).unwrap();
        let info = stack.bridge_info(ns, bridge).unwrap();
        assert_eq!(info.designated_root, bpdu.root_id);
        assert_eq!(info.root_path_cost, 100);
        assert_eq!(info.root_port, 1);
        first.frames.lock().unwrap().clear();
        stack.bridge_stp_tick(now.saturating_add(3_000_000_000));
        assert!(first.frames.lock().unwrap().iter().any(|frame|
            frame.len() == crate::ethernet::ETH_HDR_LEN + LLC_LEN + 4
                && frame[crate::ethernet::ETH_HDR_LEN + LLC_LEN..] == [0, 0, 0, 0x80]));
    }

    #[test]
    fn topology_notifications_ack_designated_ports_and_stop_on_root_ack() {
        let stack = NetStack::new();
        let owner = crate::net_ns::test_support::allocate_namespace();
        let bridge_dev = Arc::new(Capture::new(crate::MacAddr([2, 0, 0, 0, 10, 1])));
        let root = Arc::new(Capture::new(crate::MacAddr([2, 0, 0, 0, 10, 2])));
        let designated = Arc::new(Capture::new(crate::MacAddr([2, 0, 0, 0, 10, 3])));
        let ns = owner.id().as_u64();
        let bridge = stack.ifaces.register_in_ns(bridge_dev.clone(), ns);
        let root_id = stack.ifaces.register_in_ns(root.clone(), ns);
        let designated_id = stack.ifaces.register_in_ns(designated.clone(), ns);
        let rtnl = stack.rtnl_lock();
        stack.bridge_create_in_rtnl(&rtnl, bridge, ns, bridge_dev.mac()).unwrap();
        stack.bridge_add_port_in_rtnl(&rtnl, bridge, root_id).unwrap();
        stack.bridge_add_port_in_rtnl(&rtnl, bridge, designated_id).unwrap();
        drop(rtnl);
        stack.bridge_enable_stp(ns, bridge).unwrap();
        let superior = StpConfigBpdu { topology_change: false, topology_change_ack: false,
            root_id: [0x70, 0, 0, 0, 0, 0, 0, 1], root_path_cost: 0,
            bridge_id: [0x70, 0, 0, 0, 0, 0, 0, 2], port_id: 0x8001,
            message_age: 0, max_age: 2_000, hello_time: 200, forward_delay: 1_500 };
        stack.deliver_ethernet(root_id, &stp_wire(crate::MacAddr([2, 0, 0, 0, 10, 8]), &superior.encode())).unwrap();
        root.frames.lock().unwrap().clear(); designated.frames.lock().unwrap().clear();
        stack.deliver_ethernet(designated_id, &stp_wire(crate::MacAddr([2, 0, 0, 0, 10, 9]), &tcn_bpdu())).unwrap();
        let now = super::super::monotonic_ns_safe().saturating_add(30_000_000);
        stack.bridge_stp_tick(now);
        let frames = designated.frames.lock().unwrap();
        let ack = frames.iter().filter_map(|frame| StpConfigBpdu::parse(&frame[crate::ethernet::ETH_HDR_LEN + LLC_LEN..]))
            .find(|bpdu| bpdu.topology_change_ack).unwrap();
        assert!(ack.topology_change_ack);
        drop(frames);
        assert!(root.frames.lock().unwrap().iter().any(|frame|
            frame.len() == crate::ethernet::ETH_HDR_LEN + LLC_LEN + 4));
        root.frames.lock().unwrap().clear(); designated.frames.lock().unwrap().clear();
        let mut announced = superior.clone(); announced.topology_change = true;
        stack.deliver_ethernet(root_id, &stp_wire(crate::MacAddr([2, 0, 0, 0, 10, 8]), &announced.encode())).unwrap();
        let active = stack.bridge_info(ns, bridge).unwrap();
        assert_eq!(active.topology_change, 1);
        assert_eq!(active.ageing_time, 3_000);
        let mut acknowledged = superior.clone(); acknowledged.topology_change_ack = true;
        stack.deliver_ethernet(root_id, &stp_wire(crate::MacAddr([2, 0, 0, 0, 10, 8]), &acknowledged.encode())).unwrap();
        let restored = stack.bridge_info(ns, bridge).unwrap();
        assert_eq!(restored.topology_change, 0);
        assert_eq!(restored.ageing_time, 30_000);
        assert_eq!(restored.topology_change_detected, 0);
        stack.bridge_stp_tick(now.saturating_add(3_000_000_000));
        assert!(!root.frames.lock().unwrap().iter().any(|frame|
            frame.len() == crate::ethernet::ETH_HDR_LEN + LLC_LEN + 4));
        assert!(designated.frames.lock().unwrap().iter().filter_map(|frame|
            StpConfigBpdu::parse(&frame[crate::ethernet::ETH_HDR_LEN + LLC_LEN..]))
            .all(|bpdu| !bpdu.topology_change_ack));
    }
}
