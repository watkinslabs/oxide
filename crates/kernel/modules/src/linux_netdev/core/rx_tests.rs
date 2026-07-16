use super::*;

struct RxDev;

impl NetDev for RxDev {
    fn name(&self) -> &str { "module-rx-test" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, _pkt: Pkt) -> Result<(), NetError> { Ok(()) }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> net::NamespaceDropAction {
        net::NamespaceDropAction::Destroy
    }
}

fn rx_skb(dev: *mut LinuxNetDevice) -> *mut LinuxSkBuff {
    let mut frame = [0u8; ETH_HLEN + 28];
    frame[ETHERTYPE_OFFSET] = (net::addr::eth_p::ARP >> u8::BITS) as u8;
    frame[ETHERTYPE_OFFSET + 1] = net::addr::eth_p::ARP as u8;
    let skb = skb::skb_from_frame(&frame, dev, 0);
    assert!(!skb.is_null());
    // SAFETY: test owns skb and device; Ethernet header is present.
    unsafe { assert_eq!(skb::eth_type_trans(skb, dev), net::addr::eth_p::ARP); }
    skb
}

#[test]
fn netif_rx_accepts_exact_live_generation() {
    let iface = net::sock::stack().ifaces.register(Arc::new(RxDev));
    // SAFETY: test owns this allocation until explicit free.
    let dev = unsafe { netalloc::alloc_etherdev(0) };
    assert!(!dev.is_null());
    // SAFETY: test exclusively owns dev and skb across synchronous receive.
    unsafe {
        (*dev).ifindex = iface.raw();
        assert_eq!(netif_rx(rx_skb(dev)), NET_RX_SUCCESS);
        assert!(net::sock::stack().unregister_iface(iface));
        netalloc::free_netdev(dev);
    }
}

#[test]
fn netif_rx_rejects_skb_stamped_before_retirement() {
    let iface = net::sock::stack().ifaces.register(Arc::new(RxDev));
    // SAFETY: test owns this allocation until explicit free.
    let dev = unsafe { netalloc::alloc_etherdev(0) };
    assert!(!dev.is_null());
    // SAFETY: test owns dev and keeps it alive after interface retirement.
    unsafe {
        (*dev).ifindex = iface.raw();
        let skb = rx_skb(dev);
        assert!(net::sock::stack().unregister_iface(iface));
        assert_eq!(netif_rx(skb), NET_RX_DROP);
        netalloc::free_netdev(dev);
    }
}
