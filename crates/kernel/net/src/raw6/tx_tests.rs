use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as LockClass};

use crate::addr::{IpProto, Ipv6Addr, MacAddr};
use crate::netdev::{NetDev, NetError, NetResult};
use crate::pkt::Pkt;
use crate::route6::Route6Entry;
use crate::stack::NetStack;

use super::{Raw6Endpoint, Raw6SendMode};

const LOCAL: Ipv6Addr = Ipv6Addr([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const ROUTE_DST: Ipv6Addr = Ipv6Addr([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
const HEADER_DST: Ipv6Addr = Ipv6Addr([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);

struct CaptureDev {
    mtu: u32,
    packets: Spinlock<Vec<Vec<u8>>, LockClass>,
}

impl NetDev for CaptureDev {
    fn name(&self) -> &str { "raw6test0" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { self.mtu }
    fn xmit(&self, packet: Pkt) -> NetResult<()> {
        self.packets.lock().push(packet.data().to_vec());
        Ok(())
    }
}

fn routed_capture(mtu: u32) -> (NetStack, Arc<CaptureDev>) {
    let stack = NetStack::new();
    let dev = Arc::new(CaptureDev { mtu, packets: Spinlock::new(Vec::new()) });
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn NetDev>);
    stack.routes6.add(Route6Entry {
        dst: ROUTE_DST, prefix_len: 128, iface, gateway: None, src_hint: Some(LOCAL),
    });
    (stack, dev)
}

fn caller_packet(len: usize) -> Vec<u8> {
    let mut bytes = vec![0xa5; len];
    if len < crate::ipv6::IPV6_HDR_LEN { return bytes; }
    bytes[0] = 0x16;
    bytes[4..6].copy_from_slice(&0xdead_u16.to_be_bytes());
    bytes[6] = 253;
    bytes[7] = 9;
    bytes[8..24].copy_from_slice(&Ipv6Addr::ANY.0);
    bytes[24..40].copy_from_slice(&HEADER_DST.0);
    bytes
}

#[test]
fn hdrincl_transmits_caller_bytes_without_header_validation_or_rewriting() {
    let (stack, dev) = routed_capture(96);
    let endpoint = Raw6Endpoint::standalone(0, IpProto::Raw as u8);
    let bytes = caller_packet(64);

    stack.send_raw6(&endpoint, ROUTE_DST, None, None, &bytes, 64,
        crate::uapi::IPV6_PMTUDISC_WANT).unwrap();

    assert_eq!(&*dev.packets.lock(), &[bytes]);
}

#[test]
fn hdrincl_enforces_only_base_header_minimum_and_route_mtu() {
    let (stack, dev) = routed_capture(64);
    let endpoint = Raw6Endpoint::standalone(0, IpProto::Raw as u8);

    assert_eq!(stack.send_raw6(&endpoint, ROUTE_DST, None, None,
        &caller_packet(crate::ipv6::IPV6_HDR_LEN - 1), 64,
        crate::uapi::IPV6_PMTUDISC_WANT), Err(NetError::Einval));
    assert_eq!(stack.send_raw6(&endpoint, ROUTE_DST, None, None,
        &caller_packet(65), 64, crate::uapi::IPV6_PMTUDISC_WANT), Err(NetError::Emsgsize));
    assert!(dev.packets.lock().is_empty());
}

#[test]
fn enabled_udp_checksum_zero_is_transmitted_as_ffff() {
    let endpoint = Raw6Endpoint::standalone(0, IpProto::Udp as u8);
    endpoint.set_checksum(6).unwrap();
    let payload = [0xbf, 0xe1, 0, 0, 0, 0, 0, 0];

    let prepared = endpoint.prepare_send(LOCAL, ROUTE_DST, None, &payload).unwrap();

    assert_eq!(prepared.mode, Raw6SendMode::KernelHeader);
    assert_eq!(&prepared.bytes[6..8], &[0xff, 0xff]);
}
