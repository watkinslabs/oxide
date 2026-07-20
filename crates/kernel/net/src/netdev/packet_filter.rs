use super::*;

pub const PACKET_LINK_ADDRESS_MAX: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketLinkAddress {
    pub len: u8,
    pub bytes: [u8; PACKET_LINK_ADDRESS_MAX],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PacketRxMode {
    pub promiscuous: bool,
    pub all_multicast: bool,
    pub multicast: Vec<PacketLinkAddress>,
    pub unicast: Vec<PacketLinkAddress>,
}

pub(crate) struct PacketDeviceFilter {
    state: Spinlock<PacketDeviceFilterState, SocketLockClass>,
}

#[derive(Default)]
struct PacketDeviceFilterState {
    admin_promiscuous: bool,
    admin_all_multicast: bool,
    promisc_refs: usize,
    allmulti_refs: usize,
    multicast: Vec<(PacketLinkAddress, usize)>,
    unicast: Vec<(PacketLinkAddress, usize)>,
}

impl PacketDeviceFilter {
    pub(crate) const fn new() -> Self {
        Self { state: Spinlock::new(PacketDeviceFilterState {
            admin_promiscuous: false, admin_all_multicast: false,
            promisc_refs: 0, allmulti_refs: 0,
            multicast: Vec::new(), unicast: Vec::new(),
        }) }
    }

    fn update(rows: &mut Vec<(PacketLinkAddress, usize)>, address: PacketLinkAddress,
              add: bool) {
        if let Some(index) = rows.iter().position(|(current, _)| *current == address) {
            if add { rows[index].1 = rows[index].1.saturating_add(1); }
            else if rows[index].1 > 1 { rows[index].1 -= 1; }
            else { rows.remove(index); }
        } else if add { rows.push((address, 1)); }
    }

    /// Apply one device-wide packet membership reference. # C: O(N addresses)
    pub(crate) fn apply(&self, kind: u16, address: PacketLinkAddress, add: bool)
        -> PacketRxMode {
        let mut state = self.state.lock();
        match kind {
            crate::uapi::PACKET_MR_MULTICAST => Self::update(&mut state.multicast, address, add),
            crate::uapi::PACKET_MR_PROMISC => {
                if add { state.promisc_refs = state.promisc_refs.saturating_add(1); }
                else { state.promisc_refs = state.promisc_refs.saturating_sub(1); }
            }
            crate::uapi::PACKET_MR_ALLMULTI => {
                if add { state.allmulti_refs = state.allmulti_refs.saturating_add(1); }
                else { state.allmulti_refs = state.allmulti_refs.saturating_sub(1); }
            }
            crate::uapi::PACKET_MR_UNICAST => Self::update(&mut state.unicast, address, add),
            _ => {}
        }
        Self::snapshot(&state)
    }

    /// Remove every packet-derived reference while retaining admin intent. # C: O(N addresses)
    pub(crate) fn clear_memberships(&self) -> PacketRxMode {
        let mut state = self.state.lock();
        state.promisc_refs = 0;
        state.allmulti_refs = 0;
        state.multicast.clear();
        state.unicast.clear();
        Self::snapshot(&state)
    }

    /// Apply explicitly changed administrative receive-mode flags. # C: O(N addresses)
    pub(crate) fn update_admin(&self, new: u32, change: u32) -> PacketRxMode {
        let mut state = self.state.lock();
        if change & iff::IFF_PROMISC != 0 {
            state.admin_promiscuous = new & iff::IFF_PROMISC != 0;
        }
        if change & iff::IFF_ALLMULTI != 0 {
            state.admin_all_multicast = new & iff::IFF_ALLMULTI != 0;
        }
        Self::snapshot(&state)
    }

    /// Snapshot effective receive mode and unique addresses. # C: O(N addresses)
    pub(crate) fn current(&self) -> PacketRxMode {
        Self::snapshot(&self.state.lock())
    }

    fn snapshot(state: &PacketDeviceFilterState) -> PacketRxMode {
        PacketRxMode {
            promiscuous: state.admin_promiscuous || state.promisc_refs != 0,
            all_multicast: state.admin_all_multicast || state.allmulti_refs != 0,
            multicast: state.multicast.iter().map(|(address, _)| *address).collect(),
            unicast: state.unicast.iter().map(|(address, _)| *address).collect(),
        }
    }
}

impl IfaceRegistry {
    /// Apply Linux SIOCADDMULTI/SIOCDELMULTI to one live device generation. # C: O(N interfaces + N addresses)
    pub fn legacy_multicast_in(&self, rtnl: &crate::RtnlGuard<'_>, net_ns: u64,
        name: &str, address: &[u8], add: bool) -> NetResult<()> {
        if !self.guard_matches(rtnl) { return Err(NetError::Enodev); }
        let (iface, generation, link_address) = {
            let g = self.inner.lock();
            let entry = g.entries.iter().find(|entry| entry.name == name && entry.ns == net_ns
                && entry.ingress.live() && entry.ingress.ready()).ok_or(NetError::Enodev)?;
            if !entry.dev.supports_packet_rx_mode() { return Err(NetError::Einval); }
            let length = entry.dev.address_len() as usize;
            if length > address.len() || length > PACKET_LINK_ADDRESS_MAX { return Err(NetError::Einval); }
            let mut bytes = [0u8; PACKET_LINK_ADDRESS_MAX];
            bytes[..length].copy_from_slice(&address[..length]);
            (entry.id, entry.ingress.generation, PacketLinkAddress { len: length as u8, bytes })
        };
        self.update_packet_filter(rtnl, iface, net_ns, generation,
            crate::uapi::PACKET_MR_MULTICAST, link_address, add)
    }

    /// Resolve one live namespace/interface generation and address width. # C: O(N interfaces)
    pub(crate) fn packet_filter_generation(&self, rtnl: &crate::RtnlGuard<'_>,
                                            iface: NetIfaceId, net_ns: u64)
        -> NetResult<(u64, u8)> {
        if !self.guard_matches(rtnl) { return Err(NetError::Enodev); }
        let g = self.inner.lock();
        let entry = g.entries.iter().find(|entry| entry.id == iface && entry.ns == net_ns
            && entry.ingress.live() && entry.ingress.ready()).ok_or(NetError::Enodev)?;
        Ok((entry.ingress.generation, entry.dev.address_len()))
    }

    /// Update one exact generation and notify its driver. # C: O(N interfaces + N addresses)
    pub(crate) fn update_packet_filter(&self, rtnl: &crate::RtnlGuard<'_>,
        iface: NetIfaceId, net_ns: u64, generation: u64, kind: u16,
        address: PacketLinkAddress, add: bool) -> NetResult<()> {
        if !self.guard_matches(rtnl) { return Err(NetError::Enodev); }
        let (dev, mode) = {
            let g = self.inner.lock();
            let entry = g.entries.iter().find(|entry| entry.id == iface && entry.ns == net_ns
                && entry.ingress.generation == generation && entry.ingress.live()
                && entry.ingress.ready()).ok_or(NetError::Enodev)?;
            let mode = entry.packet_filter.apply(kind, address, add);
            Self::store_packet_flags(entry, &mode);
            (entry.dev.clone(), mode)
        };
        dev.packet_rx_mode_changed(&mode);
        Ok(())
    }

    /// Clear packet references for one unregistering generation. # C: O(N interfaces + N addresses)
    pub(crate) fn reset_packet_filter(&self, rtnl: &crate::RtnlGuard<'_>,
                                      teardown: &IfaceTeardown) -> bool {
        if !self.guard_matches(rtnl) { return false; }
        let (dev, mode) = {
            let g = self.inner.lock();
            let Some(entry) = g.entries.iter().find(|entry| entry.id == teardown.iface()
                && entry.ns == teardown.net_ns()
                && entry.ingress.generation == teardown.generation()
                && Arc::ptr_eq(&entry.dev, &teardown.dev)) else { return false };
            let mode = entry.packet_filter.clear_memberships();
            Self::store_packet_flags(entry, &mode);
            (entry.dev.clone(), mode)
        };
        dev.packet_rx_mode_changed(&mode);
        true
    }

    fn store_packet_flags(entry: &IfaceEntry, mode: &PacketRxMode) {
        let mut flags = entry.flags.load(Ordering::Acquire);
        if mode.promiscuous { flags |= iff::IFF_PROMISC; } else { flags &= !iff::IFF_PROMISC; }
        if mode.all_multicast { flags |= iff::IFF_ALLMULTI; } else { flags &= !iff::IFF_ALLMULTI; }
        entry.flags.store(flags, Ordering::Release);
    }

    #[cfg(test)]
    /// Snapshot one hosted interface's effective packet mode. # C: O(N interfaces + N addresses)
    pub(crate) fn packet_rx_mode(&self, iface: NetIfaceId, net_ns: u64)
        -> Option<PacketRxMode> {
        let g = self.inner.lock();
        g.entries.iter().find(|entry| entry.id == iface && entry.ns == net_ns)
            .map(|entry| entry.packet_filter.current())
    }
}
