use alloc::sync::Arc;
use alloc::vec;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::addr::{IpAddr, Ipv4Addr};
use crate::bpf_filter::SocketFilter;
use crate::mcast_filter::SocketMcast;
use crate::socket_error::{SocketErrorEntry, SO_EE_ORIGIN_ICMP};

use super::Raw4Endpoint;

const PROTOCOL: u8 = 143;
const ICMP_CODE_FRAG_NEEDED: u8 = 4;

fn endpoint(mode: i32) -> (Arc<Raw4Endpoint>, Arc<AtomicI32>) {
    let pmtudisc = Arc::new(AtomicI32::new(mode));
    let endpoint = Raw4Endpoint::new_with_pmtudisc(PROTOCOL, network_namespace::initial(),
        Arc::new(SocketFilter::new()), Arc::new(SocketMcast::new()),
        Arc::new(crate::SocketError::new()), pmtudisc.clone());
    (endpoint, pmtudisc)
}

fn frag_needed(payload: &[u8]) -> SocketErrorEntry {
    SocketErrorEntry {
        errno: syscall::errno::Errno::Emsgsize as i32,
        origin: SO_EE_ORIGIN_ICMP,
        kind: crate::icmp::ICMP_TYPE_DEST_UNREACH,
        code: ICMP_CODE_FRAG_NEEDED,
        info: 1_280,
        data: 0,
        offender: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)),
        destination_port: 0,
        ifindex: 1,
        payload: payload.to_vec(),
    }
}

#[test]
fn frag_needed_is_pending_only_for_connected_pmtu_sockets_without_recverr() {
    let (unconnected, _) = endpoint(crate::uapi::IP_PMTUDISC_WANT);
    assert!(!unconnected.publish_error(frag_needed(&[]), false));
    assert!(!unconnected.error.has());

    let (connected, pmtudisc) = endpoint(crate::uapi::IP_PMTUDISC_DONT);
    connected.connect(Ipv4Addr::new(198, 51, 100, 8), None).unwrap();
    assert!(!connected.publish_error(frag_needed(&[]), false));
    assert!(!connected.error.has());

    pmtudisc.store(crate::uapi::IP_PMTUDISC_WANT, Ordering::Release);
    assert!(connected.publish_error(frag_needed(&[]), false));
    assert_eq!(connected.error.take(), syscall::errno::Errno::Emsgsize as i32);
    assert!(!connected.error.has_extended());

    for mode in [crate::uapi::IP_PMTUDISC_DO, crate::uapi::IP_PMTUDISC_PROBE,
                 crate::uapi::IP_PMTUDISC_INTERFACE, crate::uapi::IP_PMTUDISC_OMIT] {
        let (endpoint, _) = endpoint(mode);
        endpoint.connect(Ipv4Addr::new(198, 51, 100, 8), None).unwrap();
        assert!(endpoint.publish_error(frag_needed(&[]), false));
        assert_eq!(endpoint.error.take(), syscall::errno::Errno::Emsgsize as i32);
    }
}

#[test]
fn recverr_queues_and_sets_pending_frag_needed_even_in_dont_mode() {
    let (endpoint, _) = endpoint(crate::uapi::IP_PMTUDISC_DONT);
    endpoint.error.set_recverr4(true);

    assert!(endpoint.publish_error(frag_needed(&[1, 2]), false));
    assert_eq!(endpoint.error.take(), syscall::errno::Errno::Emsgsize as i32);
    assert_eq!(endpoint.error.take_extended().unwrap().payload, vec![1, 2]);
}

#[test]
fn hdrincl_extended_error_payload_starts_at_quoted_ipv4_header() {
    let quoted_ip = [0x45, 0, 0, 28, 0, 1, 0, 0, 64, PROTOCOL, 0, 0,
        192, 0, 2, 44, 198, 51, 100, 8, 1, 2, 3, 4, 5, 6, 7, 8];
    let transport = &quoted_ip[20..];

    let (plain, _) = endpoint(crate::uapi::IP_PMTUDISC_DONT);
    plain.error.set_recverr4(true);
    assert!(plain.publish_quoted_error(frag_needed(transport), false, &quoted_ip));
    assert_eq!(plain.error.take_extended().unwrap().payload, transport);

    let (hdrincl, _) = endpoint(crate::uapi::IP_PMTUDISC_DONT);
    hdrincl.set_hdrincl(true);
    hdrincl.error.set_recverr4(true);
    assert!(hdrincl.publish_quoted_error(frag_needed(transport), false, &quoted_ip));
    assert_eq!(hdrincl.error.take_extended().unwrap().payload, quoted_ip);
}
