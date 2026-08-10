extern crate alloc;

use alloc::vec::Vec;

use super::harness::*;
use crate::genetlink::{attr, dispatch, family};
use crate::genetlink::tcp_metrics::{self, attr_id, cmd};

fn address(attrs: &mut Vec<u8>, ty: u16, addr: [u8; 4]) { attr::put(attrs, ty, &addr); }

#[test]
fn get_projects_fastopen_metrics_from_the_namespace_cache() {
    boot();
    let namespace = crate::netlink_tests::test_namespace();
    let src = net::IpAddr::V4(net::Ipv4Addr::new(192, 0, 2, 1));
    let dst = net::IpAddr::V4(net::Ipv4Addr::new(198, 51, 100, 7));
    let cookie = net::tcp_conn::fastopen::Cookie::new(&[1, 2, 3, 4, 5, 6, 7, 8], false).unwrap();
    net::tcp_fastopen::cache_learned(&namespace, src, dst, 0, 1460,
        &net::tcp_fastopen::Learned { cookie: Some(cookie), syn_lost: true, try_exp: 0,
            failed: true, data_acked: false, client_fail: 0 });
    let family = family::find_by_name(tcp_metrics::TCP_METRICS_FAMILY_NAME).unwrap();
    let mut attrs = Vec::new();
    address(&mut attrs, attr_id::ADDR_IPV4, [198, 51, 100, 7]);
    address(&mut attrs, attr_id::SADDR_IPV4, [192, 0, 2, 1]);
    let reply = dispatch::handle(&request(family.id, cmd::GET, crate::flags::NLM_F_REQUEST,
        4, &attrs), namespace.id().as_u64(), root());
    let fields = reply_attrs(&reply);
    assert_eq!(reply_cmd(&reply), Some(cmd::GET));
    assert_eq!(attr::find(fields, attr_id::FOPEN_MSS).unwrap().u16(), Some(1460));
    assert_eq!(attr::find(fields, attr_id::FOPEN_SYN_DROPS).unwrap().u16(), Some(1));
    assert_eq!(attr::find(fields, attr_id::FOPEN_COOKIE).unwrap().payload, cookie.as_bytes());
    assert_eq!(attr::find(fields, attr_id::ADDR_IPV4).unwrap().payload, &[198, 51, 100, 7]);
    assert_eq!(attr::find(fields, attr_id::SADDR_IPV4).unwrap().payload, &[192, 0, 2, 1]);
}

#[test]
fn get_requires_a_destination_and_reports_an_absent_cache_row() {
    boot();
    let family = family::find_by_name(tcp_metrics::TCP_METRICS_FAMILY_NAME).unwrap();
    let ns = crate::genetlink::mcast::initial_net_ns();
    let missing = dispatch::handle(&request(family.id, cmd::GET, crate::flags::NLM_F_REQUEST,
        4, &[]), ns, root());
    assert_eq!(reply_errno(&missing), Some(syscall::errno::Errno::Eafnosupport.as_i32()));
    let mut attrs = Vec::new();
    address(&mut attrs, attr_id::ADDR_IPV4, [203, 0, 113, 7]);
    let absent = dispatch::handle(&request(family.id, cmd::GET, crate::flags::NLM_F_REQUEST,
        4, &attrs), ns, root());
    assert_eq!(reply_errno(&absent), Some(syscall::errno::Errno::Esrch.as_i32()));
}

fn u32_attr(fields: &[u8], ty: u16) -> Option<u32> {
    let payload = attr::find(fields, ty)?.payload;
    Some(u32::from_ne_bytes(payload.get(..4)?.try_into().ok()?))
}

#[test]
fn get_projects_the_path_metrics_a_closing_connection_left_behind() {
    use net::tcp_metrics::ids;
    boot();
    let namespace = crate::netlink_tests::test_namespace();
    let src = net::IpAddr::V4(net::Ipv4Addr::new(192, 0, 2, 2));
    let dst = net::IpAddr::V4(net::Ipv4Addr::new(198, 51, 100, 8));
    let mut vals = [None; ids::COUNT];
    vals[ids::RTT] = Some(2_500);
    vals[ids::RTTVAR] = Some(400);
    vals[ids::CWND] = Some(17);
    net::tcp_metrics::pin(&namespace, src, dst, 0, vals);

    let family = family::find_by_name(tcp_metrics::TCP_METRICS_FAMILY_NAME).unwrap();
    let mut attrs = Vec::new();
    address(&mut attrs, attr_id::ADDR_IPV4, [198, 51, 100, 8]);
    address(&mut attrs, attr_id::SADDR_IPV4, [192, 0, 2, 2]);
    let reply = dispatch::handle(&request(family.id, cmd::GET, crate::flags::NLM_F_REQUEST,
        4, &attrs), namespace.id().as_u64(), root());
    let nest = attr::find(reply_attrs(&reply), attr_id::VALS).expect("the metrics nest").payload;

    // The stored microsecond value goes out raw AND divided down, so a
    // reader looking at either attribute sees the same round trip.
    assert_eq!(u32_attr(nest, ids::ATTR_RTT_US), Some(2_500));
    assert_eq!(u32_attr(nest, ids::attr(ids::RTT)), Some(2));
    assert_eq!(u32_attr(nest, ids::ATTR_RTTVAR_US), Some(400));
    assert_eq!(u32_attr(nest, ids::attr(ids::RTTVAR)), Some(1),
        "a sub-millisecond variation reports the floor, never as absent");
    assert_eq!(u32_attr(nest, ids::attr(ids::CWND)), Some(17));
    assert_eq!(u32_attr(nest, ids::attr(ids::SSTHRESH)), None,
        "a slot holding nothing is omitted rather than reported as zero");
}

#[test]
fn a_row_with_no_path_metrics_carries_no_nest_at_all() {
    boot();
    let namespace = crate::netlink_tests::test_namespace();
    let src = net::IpAddr::V4(net::Ipv4Addr::new(192, 0, 2, 3));
    let dst = net::IpAddr::V4(net::Ipv4Addr::new(198, 51, 100, 9));
    net::tcp_fastopen::cache_learned(&namespace, src, dst, 0, 1460,
        &net::tcp_fastopen::Learned { cookie: None, syn_lost: false, try_exp: 0,
            failed: false, data_acked: false, client_fail: 0 });
    let family = family::find_by_name(tcp_metrics::TCP_METRICS_FAMILY_NAME).unwrap();
    let mut attrs = Vec::new();
    address(&mut attrs, attr_id::ADDR_IPV4, [198, 51, 100, 9]);
    address(&mut attrs, attr_id::SADDR_IPV4, [192, 0, 2, 3]);
    let reply = dispatch::handle(&request(family.id, cmd::GET, crate::flags::NLM_F_REQUEST,
        4, &attrs), namespace.id().as_u64(), root());
    let fields = reply_attrs(&reply);
    assert!(attr::find(fields, attr_id::VALS).is_none(), "an empty nest is not emitted");
    assert_eq!(attr::find(fields, attr_id::FOPEN_MSS).unwrap().u16(), Some(1460),
        "the fast-open half of the same row still reports");
}

#[test]
fn del_forgets_one_destination_and_reports_one_it_never_held() {
    use net::tcp_metrics::ids;
    boot();
    let namespace = crate::netlink_tests::test_namespace();
    let src = net::IpAddr::V4(net::Ipv4Addr::new(192, 0, 2, 4));
    let dst = net::IpAddr::V4(net::Ipv4Addr::new(198, 51, 100, 10));
    let mut vals = [None; ids::COUNT];
    vals[ids::RTT] = Some(9_000);
    net::tcp_metrics::pin(&namespace, src, dst, 0, vals);

    let family = family::find_by_name(tcp_metrics::TCP_METRICS_FAMILY_NAME).unwrap();
    let mut attrs = Vec::new();
    address(&mut attrs, attr_id::ADDR_IPV4, [198, 51, 100, 10]);
    address(&mut attrs, attr_id::SADDR_IPV4, [192, 0, 2, 4]);
    let ns = namespace.id().as_u64();
    let removed = dispatch::handle(&request(family.id, cmd::DEL, crate::flags::NLM_F_REQUEST,
        4, &attrs), ns, root());
    assert_eq!(reply_errno(&removed), Some(0));
    assert!(net::tcp_metrics::cached(&namespace, src, dst).is_empty());

    let again = dispatch::handle(&request(family.id, cmd::DEL, crate::flags::NLM_F_REQUEST,
        4, &attrs), ns, root());
    assert_eq!(reply_errno(&again), Some(syscall::errno::Errno::Esrch.as_i32()),
        "a destination this namespace holds nothing for");
}
