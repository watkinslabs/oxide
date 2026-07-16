// `/proc/net/raw{,6}` rendering from namespace-owned immutable net snapshots.

use alloc::format;
use alloc::string::String;
use core::fmt::Write as _;
use net::addr::{IpAddr, Ipv6Addr};
use vfs::{Ino, InodeRef};

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

fn ipv6_hex(ip: Ipv6Addr) -> String {
    let o = ip.0;
    let a = u32::from_be_bytes([o[0], o[1], o[2], o[3]]).to_be();
    let b = u32::from_be_bytes([o[4], o[5], o[6], o[7]]).to_be();
    let c = u32::from_be_bytes([o[8], o[9], o[10], o[11]]).to_be();
    let d = u32::from_be_bytes([o[12], o[13], o[14], o[15]]).to_be();
    format!("{a:08X}{b:08X}{c:08X}{d:08X}")
}

fn raw_body(net_ns: u64) -> alloc::vec::Vec<u8> {
    let mut out = String::from(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n",
    );
    let mut sl: u32 = 0;
    for row in net::global_stack().raw_diag_snapshot_in(net_ns, AF_INET) {
        if let (IpAddr::V4(local), IpAddr::V4(remote)) = (row.local_ip, row.remote_ip) {
            let _ = writeln!(out, "{:5}: {:08X}:{:04X} {:08X}:0000 07 00000000:{:08X} 00:00000000 00000000     0        0 0 2 0000000000000000 {}",
                sl, local.as_u32().to_be(), row.protocol, remote.as_u32().to_be(), row.rqueue, row.drops);
            sl += 1;
        }
    }
    out.into_bytes()
}

fn raw6_body(net_ns: u64) -> alloc::vec::Vec<u8> {
    let mut out = String::from(
        "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n",
    );
    let mut sl: u32 = 0;
    for row in net::global_stack().raw_diag_snapshot_in(net_ns, AF_INET6) {
        if let (IpAddr::V6(local), IpAddr::V6(remote)) = (row.local_ip, row.remote_ip) {
            let _ = writeln!(out, "{:5}: {}:{:04X} {}:0000 07 00000000:{:08X} 00:00000000 00000000     0        0 0 2 0000000000000000 {}",
                sl, ipv6_hex(local), row.protocol, ipv6_hex(remote), row.rqueue, row.drops);
            sl += 1;
        }
    }
    out.into_bytes()
}

/// `/proc/net/raw` namespace-relative immutable-snapshot inode. # C: O(1)
pub fn make_proc_net_raw() -> InodeRef {
    crate::dyn_file::make_ns_gen_file(crate::ids::NET_RAW as Ino, net::netdev::current_net_ns, raw_body)
}

/// `/proc/net/raw6` namespace-relative immutable-snapshot inode. # C: O(1)
pub fn make_proc_net_raw6() -> InodeRef {
    crate::dyn_file::make_ns_gen_file(crate::ids::NET_RAW6 as Ino, net::netdev::current_net_ns, raw6_body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use net::bpf_filter::SocketFilter;
    use net::mcast_filter::SocketMcast;
    use vfs::{Dentry, File, OpenFlags};

    fn raw4(protocol: u8, namespace: network_namespace::NetworkNamespaceRef) -> Arc<net::raw4::Raw4Endpoint> {
        net::raw4::Raw4Endpoint::new(protocol, namespace, Arc::new(SocketFilter::new()),
            Arc::new(SocketMcast::new()), Arc::new(net::SocketError::new()))
    }

    fn new_namespace() -> network_namespace::NetworkNamespaceRef {
        let _ = net::net_ns::install_final_drop_pending_notifier();
        network_namespace::allocate(namespace_identity::initial(
            namespace_identity::NamespaceKind::User)).unwrap()
    }

    #[test]
    fn canonical_rows_are_namespace_scoped() {
        let namespace = new_namespace();
        let other_namespace = new_namespace();
        let ns = namespace.id().as_u64();
        let stack = net::global_stack();
        let raw = raw4(143, namespace.clone());
        raw.bind(net::Ipv4Addr::new(192, 0, 2, 1), Some(net::NetIfaceId::from_raw(9))).unwrap();
        raw.connect(net::Ipv4Addr::new(198, 51, 100, 2), None).unwrap();
        let hidden = raw4(144, other_namespace);
        stack.register_raw4(&raw);
        stack.register_raw4(&hidden);

        let bytes = raw_body(ns);
        let body = core::str::from_utf8(&bytes).unwrap();
        assert!(body.starts_with("  sl  local_address rem_address   st tx_queue rx_queue"));
        assert!(body.contains("010200C0:008F 026433C6:0000 07 00000000:00000000"));
        assert!(!body.contains(":0090"));

        let local6 = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 1, 0, 0, 0, 0, 1]);
        let remote6 = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 2, 0, 0, 0, 0, 2]);
        let raw6 = Arc::new(net::raw6::Raw6Endpoint::standalone(namespace, 58));
        raw6.bind(net::raw6::Raw6Address::new(local6, 0), Some(net::NetIfaceId::from_raw(10)));
        raw6.connect(net::raw6::Raw6Address::new(remote6, 0));
        stack.register_raw6(&raw6);
        let bytes6 = raw6_body(ns);
        let body6 = core::str::from_utf8(&bytes6).unwrap();
        assert!(body6.contains(&format!("{}:003A {}:0000 07 00000000:00000000",
            ipv6_hex(local6), ipv6_hex(remote6))));

        stack.unregister_raw4(&raw);
        stack.unregister_raw4(&hidden);
        stack.unregister_raw6(&raw6);
    }

    #[test]
    fn open_keeps_immutable_raw_body() {
        let stack = net::global_stack();
        let first_endpoint = raw4(241, network_namespace::initial());
        stack.register_raw4(&first_endpoint);
        let inode = make_proc_net_raw();
        let first = File::new(Arc::clone(&inode), Dentry::new_root(Arc::clone(&inode)), OpenFlags::O_RDONLY);
        first.open_hook().unwrap();

        let second_endpoint = raw4(242, network_namespace::initial());
        stack.register_raw4(&second_endpoint);
        let mut first_buf = [0u8; 512];
        let first_n = first.read(&mut first_buf).unwrap();
        let first_body = core::str::from_utf8(&first_buf[..first_n]).unwrap();
        assert!(first_body.contains(":00F1"));
        assert!(!first_body.contains(":00F2"));

        let second = File::new(Arc::clone(&inode), Dentry::new_root(inode), OpenFlags::O_RDONLY);
        second.open_hook().unwrap();
        let mut second_buf = [0u8; 512];
        let second_n = second.read(&mut second_buf).unwrap();
        let second_body = core::str::from_utf8(&second_buf[..second_n]).unwrap();
        assert!(second_body.contains(":00F1"));
        assert!(second_body.contains(":00F2"));

        stack.unregister_raw4(&first_endpoint);
        stack.unregister_raw4(&second_endpoint);
    }
}
