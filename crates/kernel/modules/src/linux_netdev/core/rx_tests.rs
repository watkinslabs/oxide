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

#[test]
fn eth_type_trans_retains_exact_link_frame_after_pull() {
    let iface = net::sock::stack().ifaces.register(Arc::new(RxDev));
    let dev = unsafe { netalloc::alloc_etherdev(0) };
    assert!(!dev.is_null());
    // SAFETY: test exclusively owns dev and skb through synchronous extraction.
    unsafe {
        (*dev).ifindex = iface.raw();
        let skb = rx_skb(dev);
        let (l3, link, proto, stamped_iface, generation) =
            skb::skb_copy_to_vec_and_free(skb).expect("valid skb");
        let link = link.expect("eth_type_trans MAC header");
        assert_eq!(l3.len(), 28);
        assert_eq!(link.len(), ETH_HLEN + l3.len());
        assert_eq!(&link[ETH_HLEN..], l3);
        assert_eq!(proto, net::addr::eth_p::ARP);
        assert_eq!(stamped_iface, iface.raw());
        assert!(generation.is_some());
        assert!(net::sock::stack().unregister_iface(iface));
        netalloc::free_netdev(dev);
    }
}

#[test]
fn netif_rx_publishes_pulled_link_frame_to_packet_socket_once() {
    let iface = net::sock::stack().ifaces.register(Arc::new(RxDev));
    let packet = Arc::new(net::sock::InetSocket::new_packet_in(
        net::eth_p::ALL, 3, net::net_ns::initial_namespace()));
    net::sock::register_packet(&packet);
    if let net::sock::SockKind::Packet { ifindex, .. } = &*packet.kind.lock() {
        ifindex.store(iface.raw(), Ordering::Release);
    }
    let dev = unsafe { netalloc::alloc_etherdev(0) };
    assert!(!dev.is_null());
    // SAFETY: test exclusively owns dev and transfers skb ownership to netif_rx.
    unsafe {
        (*dev).ifindex = iface.raw();
        assert_eq!(netif_rx(rx_skb(dev)), NET_RX_SUCCESS);
        let kind = packet.kind.lock();
        let net::sock::SockKind::Packet { rx, .. } = &*kind else { panic!("packet socket") };
        let frames = rx.lock();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload.len(), ETH_HLEN + 28);
        assert_eq!(frames[0].addr.protocol, net::addr::eth_p::ARP);
        drop(frames); drop(kind);
        assert!(net::sock::stack().unregister_iface(iface));
        netalloc::free_netdev(dev);
    }
}

#[test]
fn skb_expansion_preserves_pulled_link_header_identity() {
    let iface = net::sock::stack().ifaces.register(Arc::new(RxDev));
    let dev = unsafe { netalloc::alloc_etherdev(0) };
    assert!(!dev.is_null());
    // SAFETY: test owns dev and skb until synchronous extraction frees the skb.
    unsafe {
        (*dev).ifindex = iface.raw();
        let skb = rx_skb(dev);
        assert_eq!(skb::pskb_expand_head(skb, 32, 16, 0), LINUX_OK);
        let (l3, link, _, _, _) = skb::skb_copy_to_vec_and_free(skb).expect("valid skb");
        let link = link.expect("preserved MAC header");
        assert_eq!(link.len(), ETH_HLEN + 28);
        assert_eq!(&link[ETH_HLEN..], l3);
        assert!(net::sock::stack().unregister_iface(iface));
        netalloc::free_netdev(dev);
    }
}
