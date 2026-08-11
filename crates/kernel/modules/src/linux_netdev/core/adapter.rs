use super::*;

impl NetDev for LinuxNetAdapter {
    fn name(&self) -> &str { &self.name }
    fn mac(&self) -> MacAddr { let dev = self.dev as *const LinuxNetDevice; if dev.is_null() { return MacAddr::ZERO; } // SAFETY: registered adapter retains its net_device until unregister_netdev removes it.
        unsafe { MacAddr(core::ptr::read((*dev).dev_addr as *const [u8; ETH_ALEN])) } }
    fn mtu(&self) -> u32 { let dev = self.dev as *const LinuxNetDevice; if dev.is_null() { return ETH_DATA_LEN; } // SAFETY: registered adapter retains its net_device until unregister_netdev removes it.
        unsafe { (*dev).mtu } }
    fn hardware_broadcast(&self) -> net::PacketLinkAddress {
        let dev = self.dev as *const LinuxNetDevice;
        if dev.is_null() { return net::PacketLinkAddress { len: 0, bytes: [0; net::PACKET_LINK_ADDRESS_MAX] }; }
        // SAFETY: registered adapter retains its net_device until unregister_netdev removes it.
        unsafe { let length = ((*dev).addr_len as usize).min(net::PACKET_LINK_ADDRESS_MAX); let mut bytes = [0; net::PACKET_LINK_ADDRESS_MAX]; bytes[..length].copy_from_slice(&(&(*dev).broadcast)[..length]); net::PacketLinkAddress { len: length as u8, bytes } }
    }
    fn set_hardware_broadcast(&self, address: net::PacketLinkAddress) -> Result<(), NetError> {
        let dev = self.dev as *mut LinuxNetDevice; if dev.is_null() { return Err(NetError::Enodev); }
        // SAFETY: registered adapter retains exclusive device address mutation through its stack callback.
        unsafe { let length = ((*dev).addr_len as usize).min(net::PACKET_LINK_ADDRESS_MAX); if address.len as usize != length { return Err(NetError::Einval); } (&mut (*dev).broadcast)[..length].copy_from_slice(&address.bytes[..length]); }
        Ok(())
    }
    fn set_mtu(&self, mtu: u32) -> Result<(), NetError> {
        let dev = self.dev as *mut LinuxNetDevice; if dev.is_null() { return Err(NetError::Enodev); }
        // SAFETY: registered adapter retains its net_device and installed driver operation table.
        let ops = unsafe { (*dev).netdev_ops }; if ops.is_null() { return Err(NetError::Enodev); }
        // SAFETY: driver operation table remains live for the registered device lifetime.
        let change = unsafe { (*ops).ndo_change_mtu }.ok_or(NetError::Eopnotsupp)?;
        // SAFETY: selected operation receives the registered driver-owned net_device pointer.
        match unsafe { change(dev, mtu) } { LINUX_OK => Ok(()), LINUX_EINVAL => Err(NetError::Einval), LINUX_ENODEV => Err(NetError::Enodev), _ => Err(NetError::Eio) }
    }
    fn set_mac(&self, mac: MacAddr) -> Result<(), NetError> {
        let dev = self.dev as *mut LinuxNetDevice; if dev.is_null() { return Err(NetError::Enodev); }
        // SAFETY: registered adapter retains its net_device and installed driver operation table.
        let ops = unsafe { (*dev).netdev_ops }; if ops.is_null() { return Err(NetError::Enodev); }
        // SAFETY: driver operation table remains live for the registered device lifetime.
        let change = unsafe { (*ops).ndo_set_mac_address }.ok_or(NetError::Eopnotsupp)?;
        let mut addr = LinuxSockAddr { family: net::uapi::ARPHRD_ETHER, data: [0; 14] }; addr.data[..6].copy_from_slice(&mac.0);
        // SAFETY: selected operation receives the registered driver-owned net_device and local socket address.
        match unsafe { change(dev, &mut addr as *mut _ as *mut c_void) } { LINUX_OK => Ok(()), LINUX_EINVAL => Err(NetError::Einval), LINUX_ENODEV => Err(NetError::Enodev), 95 => Err(NetError::Eopnotsupp), _ => Err(NetError::Eio) }
    }
    fn set_ifmap(&self, map: net::IfaceMap) -> Result<(), NetError> {
        let dev = self.dev as *mut LinuxNetDevice; if dev.is_null() { return Err(NetError::Enodev); }
        // SAFETY: registered adapter retains its net_device and installed driver operation table.
        let ops = unsafe { (*dev).netdev_ops }; if ops.is_null() { return Err(NetError::Enodev); }
        // SAFETY: driver operation table remains live for the registered device lifetime.
        let change = unsafe { (*ops).ndo_set_config }.ok_or(NetError::Eopnotsupp)?;
        let mut request = LinuxIfMap { mem_start: map.mem_start, mem_end: map.mem_end, base_addr: map.base_addr, irq: map.irq, dma: map.dma, port: map.port };
        // SAFETY: selected operation receives the registered driver-owned net_device and local request.
        match unsafe { change(dev, &mut request) } { LINUX_OK => Ok(()), LINUX_EINVAL => Err(NetError::Einval), LINUX_ENODEV => Err(NetError::Enodev), 95 => Err(NetError::Eopnotsupp), _ => Err(NetError::Eio) }
    }
    fn tx_queue_len(&self) -> u32 { let dev = self.dev as *const LinuxNetDevice; if dev.is_null() { return 0; } // SAFETY: adapter retains its registered net_device for this read.
        unsafe { (*dev).tx_queue_len } }
    fn set_tx_queue_len(&self, len: u32) -> Result<(), NetError> { let dev = self.dev as *mut LinuxNetDevice; if dev.is_null() { return Err(NetError::Enodev); } // SAFETY: stack callback serializes this registered device mutation.
        unsafe { (*dev).tx_queue_len = len; } Ok(()) }
    fn address_len(&self) -> u8 { let dev = self.dev as *const LinuxNetDevice; if dev.is_null() { return 0; } // SAFETY: adapter retains its registered net_device for this read.
        unsafe { core::cmp::min((*dev).addr_len, MAX_ADDR_LEN as u8) } }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> net::NamespaceDropAction { net::NamespaceDropAction::MoveToInitial }
    fn packet_rx_mode_changed(&self, mode: &net::PacketRxMode) {
        let dev = self.dev as *mut LinuxNetDevice; if dev.is_null() { return; }
        let mut addresses = self.rx_addresses.lock(); let (mc, uc) = addresses.update(mode);
        // SAFETY: adapter owns this registered net_device callback and preserves its address-list storage.
        unsafe { if mode.promiscuous { (*dev).flags |= IFF_PROMISC; } else { (*dev).flags &= !IFF_PROMISC; } if mode.all_multicast { (*dev).flags |= IFF_ALLMULTI; } else { (*dev).flags &= !IFF_ALLMULTI; } (*dev).mc = mc; (*dev).uc = uc; link_hw_addr_list(&mut (*dev).mc, &mut addresses.multicast); link_hw_addr_list(&mut (*dev).uc, &mut addresses.unicast); let ops = (*dev).netdev_ops; if !ops.is_null() { if let Some(set_rx_mode) = (*ops).ndo_set_rx_mode { set_rx_mode(dev); } } }
    }
    fn supports_packet_rx_mode(&self) -> bool { let dev = self.dev as *const LinuxNetDevice; if dev.is_null() { return false; } // SAFETY: adapter retains its registered net_device while querying its operation table.
        unsafe { !(*dev).netdev_ops.is_null() && (*(*dev).netdev_ops).ndo_set_rx_mode.is_some() } }
    fn xmit(&self, pkt: Pkt) -> Result<(), NetError> { self.xmit_observed(pkt, &mut |_, _, _| {}) }
    fn xmit_observed(&self, pkt: Pkt, observe: &mut dyn FnMut(&[u8], u16, usize)) -> Result<(), NetError> { self.xmit_l2_observed(pkt, MacAddr::BROADCAST, observe) }
    fn xmit_l2_observed(&self, pkt: Pkt, dst: MacAddr, observe: &mut dyn FnMut(&[u8], u16, usize)) -> Result<(), NetError> { let protocol = pkt.proto; let mut frame = alloc::vec![0; ETH_HLEN + pkt.len()]; net::ethernet::EthHdr::write_to(dst, self.mac(), protocol, &mut frame[..ETH_HLEN]); frame[ETH_HLEN..].copy_from_slice(pkt.data()); observe(&frame, protocol, ETH_HLEN); self.xmit_raw(&frame) }
    fn xmit_raw(&self, frame: &[u8]) -> Result<(), NetError> {
        let dev = self.dev as *mut LinuxNetDevice; if dev.is_null() { return Err(NetError::Enodev); }
        // SAFETY: registered adapter retains its net_device and installed driver operation table.
        let ops = unsafe { (*dev).netdev_ops }; if ops.is_null() { return Err(NetError::Enodev); }
        // SAFETY: driver operation table remains live for the registered device lifetime.
        let start = match unsafe { (*ops).ndo_start_xmit } { Some(f) => f, None => return Err(NetError::Enodev) };
        let skb = skb::skb_from_frame(frame, dev, frame_protocol(frame)); if skb.is_null() { return Err(NetError::Enomem); }
        // SAFETY: driver xmit callback receives its registered device and a fresh owned skb.
        match unsafe { start(skb, dev) } { NETDEV_TX_OK => Ok(()), NETDEV_TX_BUSY => { // SAFETY: busy leaves skb ownership with this façade.
            unsafe { skb::kfree_skb(skb); } Err(NetError::Eagain) }, _ => Err(NetError::Eio) }
    }
    fn stats(&self) -> NetStats { let dev = self.dev as *const LinuxNetDevice; if dev.is_null() { return NetStats::default(); } // SAFETY: adapter retains its registered net_device for the statistics snapshot.
        let s = unsafe { (*dev).stats.compat }; NetStats { rx_packets: s.rx_packets, rx_bytes: s.rx_bytes, rx_errors: s.rx_errors, rx_dropped: s.rx_dropped, tx_packets: s.tx_packets, tx_bytes: s.tx_bytes, tx_errors: s.tx_errors, tx_dropped: s.tx_dropped } }
}
