//! Canonical per-interface IPv4 neighbour bindings.

use super::*;

impl NetStack {
    /// Learn IPv4 neighbours from a validated Ethernet ingress frame. # C: O(header + log N)
    pub(crate) fn arp_observe_ethernet(&self, iface: NetIfaceId, header: crate::ethernet::EthHdr,
                                       frame: &[u8])
    {
        let payload = &frame[header.hdr_len..];
        match header.ethertype {
            crate::eth_p::ARP => if let Ok(arp) = crate::arp::ArpPkt::parse(payload) {
                self.arp_learn(iface, arp.sender_ip, arp.sender_mac);
            },
            crate::eth_p::IPV4 => if let Ok(ip) = crate::ipv4::Ipv4Hdr::parse(payload) {
                self.arp_learn(iface, ip.src, header.src);
            },
            _ => {}
        }
    }

    /// Answer an ARP request only for an IPv4 address owned by this L3 interface. # C: O(frame)
    pub(crate) fn arp_answer_request(&self, lease: &crate::IngressLease,
                                     header: crate::ethernet::EthHdr, frame: &[u8]) -> NetResult<()>
    {
        if header.ethertype != crate::eth_p::ARP { return Ok(()); }
        let arp = match crate::arp::ArpPkt::parse(&frame[header.hdr_len..]) { Ok(arp) => arp, Err(_) => return Ok(()) };
        let Some((address, _)) = crate::iface_addr::primary(lease.net_ns(), lease.iface()) else { return Ok(()); };
        if arp.opcode != crate::arp::ARP_OP_REQUEST || arp.target_ip != address { return Ok(()); }
        let mac = lease.device().mac();
        let body = crate::arp::build_reply(&arp, mac);
        let mut reply = alloc::vec![0; crate::ethernet::ETH_HDR_LEN + body.len()];
        crate::ethernet::EthHdr::write_to(arp.sender_mac, mac, crate::eth_p::ARP, &mut reply);
        reply[crate::ethernet::ETH_HDR_LEN..].copy_from_slice(&body);
        let egress = self.ifaces.acquire_egress_in_ns(lease.iface(), lease.net_ns()).ok_or(NetError::Enodev)?;
        egress.xmit_raw(&reply)
    }

    /// Learn one IPv4-to-Ethernet binding on the interface that owns L3 ingress. # C: O(log N)
    pub fn arp_learn(&self, iface: NetIfaceId, ip: Ipv4Addr, mac: MacAddr) {
        let mut rows = self.arp.lock();
        if rows.get(&(iface, ip)).is_some_and(|entry| entry.permanent) { return; }
        rows.insert((iface, ip), ArpNeighbor { mac,
            learned_ns: super::monotonic_ns_safe(), permanent: false });
    }

    /// Resolve one live IPv4 neighbour binding for an egress interface. # C: O(log N)
    pub fn arp_lookup(&self, iface: NetIfaceId, ip: Ipv4Addr) -> Option<MacAddr> {
        let now = super::monotonic_ns_safe();
        let mut rows = self.arp.lock();
        let mac = rows.get(&(iface, ip)).and_then(|entry| (entry.permanent || now == 0
            || entry.learned_ns == 0 || now.saturating_sub(entry.learned_ns) <= crate::arp::ARP_STALE_NS)
            .then_some(entry.mac));
        if mac.is_none() { rows.remove(&(iface, ip)); }
        mac
    }

    /// Remove an administratively installed IPv4 neighbour binding. # C: O(log N)
    pub fn arp_remove(&self, iface: NetIfaceId, ip: Ipv4Addr) -> Option<MacAddr> {
        self.arp.lock().remove(&(iface, ip)).map(|entry| entry.mac)
    }

    /// Install one permanent IPv4-to-Ethernet binding from the control plane. # C: O(log N)
    pub fn arp_set_permanent(&self, iface: NetIfaceId, ip: Ipv4Addr, mac: MacAddr) {
        self.arp.lock().insert((iface, ip), ArpNeighbor { mac, learned_ns: 0, permanent: true });
    }

    /// Snapshot one neighbour's link address and permanence for a control ABI reader. # C: O(log N)
    pub fn arp_entry(&self, iface: NetIfaceId, ip: Ipv4Addr) -> Option<(MacAddr, bool)> {
        let now = super::monotonic_ns_safe();
        let mut rows = self.arp.lock();
        let row = rows.get(&(iface, ip)).and_then(|entry| (entry.permanent || now == 0
            || entry.learned_ns == 0 || now.saturating_sub(entry.learned_ns) <= crate::arp::ARP_STALE_NS)
            .then_some((entry.mac, entry.permanent)));
        if row.is_none() { rows.remove(&(iface, ip)); }
        row
    }

    /// Drop every IPv4 neighbour binding belonging to a departing interface. # C: O(N)
    pub(crate) fn arp_remove_iface(&self, iface: NetIfaceId) {
        self.arp.lock().retain(|(id, _), _| *id != iface);
    }

    /// Reclaim stale IPv4 neighbours without waiting for a lookup. # C: O(N)
    pub fn arp_gc(&self, now: u64) {
        if now == 0 { return; }
        self.arp.lock().retain(|_, entry| entry.permanent || entry.learned_ns == 0
            || now.saturating_sub(entry.learned_ns) <= crate::arp::ARP_STALE_NS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permanent_binding_survives_expiry_and_reports_its_state() {
        let stack = NetStack::new();
        let iface = NetIfaceId::from_raw(901);
        let ip = Ipv4Addr::new(192, 0, 2, 1);
        let mac = MacAddr([2, 0, 0, 0, 9, 1]);
        stack.arp_set_permanent(iface, ip, mac);
        stack.arp_gc(u64::MAX);
        assert_eq!(stack.arp_entry(iface, ip), Some((mac, true)));
        assert_eq!(stack.arp_remove(iface, ip), Some(mac));
        assert_eq!(stack.arp_entry(iface, ip), None);
    }

    #[test]
    fn learning_cannot_replace_a_permanent_binding() {
        let stack = NetStack::new();
        let iface = NetIfaceId::from_raw(902);
        let ip = Ipv4Addr::new(192, 0, 2, 2);
        let permanent = MacAddr([2, 0, 0, 0, 9, 2]);
        stack.arp_set_permanent(iface, ip, permanent);
        stack.arp_learn(iface, ip, MacAddr([2, 0, 0, 0, 9, 3]));
        assert_eq!(stack.arp_entry(iface, ip), Some((permanent, true)));
    }
}
