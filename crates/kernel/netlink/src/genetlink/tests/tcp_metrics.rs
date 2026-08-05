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
