use super::*;
use ::core::sync::atomic::{AtomicUsize, Ordering};

static PRE_ROUTING_CALLS: AtomicUsize = AtomicUsize::new(0);
static PRE_ROUTING_LEN: AtomicUsize = AtomicUsize::new(0);
static PRE_ROUTING_FLAGS: AtomicUsize = AtomicUsize::new(usize::MAX);

fn observe_pre_routing(_namespace: u64, hook: u32, packet: &[u8], _family: u8)
    -> crate::netfilter_hook::NfHookResult
{
    if hook == NF_INET_PRE_ROUTING {
        PRE_ROUTING_CALLS.fetch_add(1, Ordering::AcqRel);
        PRE_ROUTING_LEN.store(packet.len(), Ordering::Release);
        PRE_ROUTING_FLAGS.store(u16::from_be_bytes([packet[6], packet[7]]) as usize,
            Ordering::Release);
    }
    crate::netfilter_hook::NfHookResult::ACCEPT
}

fn fragment(id: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = alloc::vec![0u8; IPV4_HDR_LEN + payload.len()];
    let mut hdr = Ipv4Hdr::build(Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK,
        IpProto::Udp, payload.len() as u16, id);
    hdr.flags_frag = flags;
    hdr.checksum = 0;
    let mut header = [0u8; IPV4_HDR_LEN];
    hdr.write_to(&mut header);
    hdr.checksum = crate::ipv4::ip_checksum(&header);
    hdr.write_to(&mut packet[..IPV4_HDR_LEN]);
    packet[IPV4_HDR_LEN..].copy_from_slice(payload);
    packet
}

#[test]
fn prerouting_receives_one_reassembled_ipv4_datagram() {
    let domain = crate::hosted_fixture::init_net_domain();
    domain.set_nf_hook(observe_pre_routing);
    PRE_ROUTING_CALLS.store(0, Ordering::Release);
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let mut udp = [0u8; 16];
    crate::udp::UdpHdr::build_into(1000, 1001, Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK,
        b"abcdefgh", &mut udp);
    let first = fragment(91, crate::ipv4::IPV4_FLAG_MORE_FRAGMENTS, &udp[..8]);
    let last = fragment(91, 1, &udp[8..]);

    stack.deliver_rx(iface, &first).unwrap();
    assert_eq!(PRE_ROUTING_CALLS.load(Ordering::Acquire), 0);
    stack.deliver_rx(iface, &last).unwrap();

    assert_eq!(PRE_ROUTING_CALLS.load(Ordering::Acquire), 1);
    assert_eq!(PRE_ROUTING_LEN.load(Ordering::Acquire), IPV4_HDR_LEN + 16);
    assert_eq!(PRE_ROUTING_FLAGS.load(Ordering::Acquire), 0);
}
