extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::addr::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::stack::NetStack;
use crate::tcp_state::TcpState;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InetDiagSnapshot {
    pub family: u8,
    pub protocol: u8,
    pub state: u8,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub ifindex: u32,
    pub rqueue: u32,
    pub wqueue: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RawDiagSnapshot {
    pub family: u8,
    pub protocol: u8,
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub ifindex: u32,
    pub rqueue: u32,
    pub drops: u32,
}

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// Linux TCP_* inet_diag state numbers from include/net/tcp_states.h.
const TCP_ESTABLISHED: u8 = 1;
const TCP_SYN_SENT: u8 = 2;
const TCP_SYN_RECV: u8 = 3;
const TCP_FIN_WAIT1: u8 = 4;
const TCP_FIN_WAIT2: u8 = 5;
const TCP_TIME_WAIT: u8 = 6;
const TCP_CLOSE: u8 = 7;
const TCP_CLOSE_WAIT: u8 = 8;
const TCP_LAST_ACK: u8 = 9;
const TCP_LISTEN: u8 = 10;
const TCP_CLOSING: u8 = 11;

fn family(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    }
}

fn tcp_diag_state(state: TcpState) -> u8 {
    match state {
        TcpState::Closed => TCP_CLOSE,
        TcpState::Listen => TCP_LISTEN,
        TcpState::SynSent => TCP_SYN_SENT,
        TcpState::SynRecv => TCP_SYN_RECV,
        TcpState::Established => TCP_ESTABLISHED,
        TcpState::FinWait1 => TCP_FIN_WAIT1,
        TcpState::FinWait2 => TCP_FIN_WAIT2,
        TcpState::CloseWait => TCP_CLOSE_WAIT,
        TcpState::Closing => TCP_CLOSING,
        TcpState::LastAck => TCP_LAST_ACK,
        TcpState::TimeWait => TCP_TIME_WAIT,
    }
}

impl NetStack {
    /// Snapshot raw sockets visible in one network namespace. # C: O(raw sockets + queued IPv4 datagrams)
    pub fn raw_diag_snapshot_in(&self, net_ns: u64, family: u8) -> Vec<RawDiagSnapshot> {
        let tables = self.inet_tables(net_ns);
        let mut out = Vec::new();
        match family {
            AF_INET => for endpoint in tables.raw4.all_endpoints() {
                let state = endpoint.snapshot();
                if !state.accepting { continue; }
                out.push(RawDiagSnapshot {
                    family, protocol: endpoint.protocol(), local_ip: IpAddr::V4(state.local),
                    remote_ip: IpAddr::V4(state.remote.unwrap_or(Ipv4Addr::ANY)),
                    ifindex: state.bound_iface.map(|id| id.raw()).unwrap_or(0),
                    rqueue: state.queued_bytes.min(u32::MAX as usize) as u32,
                    drops: state.drops,
                });
            },
            AF_INET6 => for endpoint in tables.raw6.all_endpoints() {
                let state = endpoint.snapshot();
                if !state.accepting { continue; }
                out.push(RawDiagSnapshot {
                    family, protocol: endpoint.protocol(), local_ip: IpAddr::V6(state.local.addr),
                    remote_ip: IpAddr::V6(state.peer.map(|peer| peer.addr).unwrap_or(Ipv6Addr::ANY)),
                    ifindex: state.bound_iface.map(|id| id.raw()).unwrap_or(0),
                    rqueue: state.queued_bytes.min(u32::MAX as usize) as u32,
                    drops: 0,
                });
            },
            _ => {}
        }
        out
    }

    /// Snapshot TCP listeners, TCP connections, and UDP bindings for
    /// NETLINK_SOCK_DIAG inet_diag dumps. # C: O(TCP + UDP sockets)
    #[cfg(test)]
    pub fn inet_diag_snapshot(&self, protocol: u8) -> Vec<InetDiagSnapshot> {
        self.inet_diag_snapshot_in(0, protocol)
    }

    /// Snapshot transport state visible in one network namespace. # C: O(TCP + UDP sockets)
    pub fn inet_diag_snapshot_in(&self, net_ns: u64, protocol: u8) -> Vec<InetDiagSnapshot> {
        let mut out = Vec::new();
        let tables = self.inet_tables(net_ns);
        match protocol {
            IPPROTO_TCP => {
                for entries in tables.tcp_listens.lock().values() {
                    for listener in entries {
                        out.push(InetDiagSnapshot {
                            family: family(listener.local.ip),
                            protocol,
                            state: TCP_LISTEN,
                            local_ip: listener.local.ip,
                            local_port: listener.local.port,
                            remote_ip: match listener.local.ip {
                                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::ANY),
                                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::ANY),
                            },
                            remote_port: 0,
                            ifindex: listener.bound_iface().map(|id| id.raw()).unwrap_or(0),
                            rqueue: listener.accept_q.lock().len() as u32,
                            wqueue: 0,
                        });
                    }
                }
                for entry in tables.tcp_conns.lock().values() {
                    let conn = entry.conn.lock();
                    out.push(InetDiagSnapshot {
                        family: family(conn.local.ip),
                        protocol,
                        state: tcp_diag_state(conn.state),
                        local_ip: conn.local.ip,
                        local_port: conn.local.port,
                        remote_ip: conn.remote.ip,
                        remote_port: conn.remote.port,
                        ifindex: entry.bound_iface().map(|id| id.raw()).unwrap_or(0),
                        rqueue: conn.recv_buf.len() as u32,
                        wqueue: conn.send_buf.len() as u32,
                    });
                }
            }
            IPPROTO_UDP => {
                for q in tables.udp.lock().values().flatten() {
                    let peer = *q.peer.lock();
                    out.push(InetDiagSnapshot {
                        family: AF_INET,
                        protocol,
                        state: if peer.is_some() { TCP_ESTABLISHED } else { TCP_CLOSE },
                        local_ip: IpAddr::V4(q.bound_ip),
                        local_port: q.bound_port,
                        remote_ip: IpAddr::V4(peer.map(|p| p.0).unwrap_or(Ipv4Addr::ANY)),
                        remote_port: peer.map(|p| p.1).unwrap_or(0),
                        ifindex: q.bound_ifindex.load(Ordering::Acquire),
                        rqueue: q.queued_bytes() as u32,
                        wqueue: 0,
                    });
                }
                for q in tables.udp6.lock().values().flatten() {
                    let peer = *q.peer.lock();
                    out.push(InetDiagSnapshot {
                        family: AF_INET6,
                        protocol,
                        state: if peer.is_some() { TCP_ESTABLISHED } else { TCP_CLOSE },
                        local_ip: IpAddr::V6(q.bound_ip),
                        local_port: q.bound_port,
                        remote_ip: IpAddr::V6(peer.map(|p| p.0).unwrap_or(Ipv6Addr::ANY)),
                        remote_port: peer.map(|p| p.1).unwrap_or(0),
                        ifindex: q.bound_ifindex.load(Ordering::Acquire),
                        rqueue: q.queued_bytes() as u32,
                        wqueue: 0,
                    });
                }
            }
            _ => {}
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::AtomicI32;
    use sync::{Socket as StackLockClass, Spinlock};

    use super::*;
    use crate::addr::NetIfaceId;
    use crate::SocketError;

    fn reuse() -> Arc<AtomicI32> { Arc::new(AtomicI32::new(1)) }
    fn dual_stack() -> Arc<AtomicI32> { Arc::new(AtomicI32::new(0)) }

    #[test]
    fn raw_diag_is_namespace_scoped_and_snapshots_tuple_queue_and_device() {
        let owner_a = crate::net_ns::test_support::allocate_namespace();
        let owner_b = crate::net_ns::test_support::allocate_namespace();
        let ns_a = owner_a.id().as_u64();
        let ns_b = owner_b.id().as_u64();
        let stack = NetStack::new();
        let raw4_a = crate::raw4::Raw4Endpoint::new(143, owner_a.clone(),
            Arc::new(crate::bpf_filter::SocketFilter::new()),
            Arc::new(crate::mcast_filter::SocketMcast::new()), Arc::new(SocketError::new()));
        raw4_a.bind(Ipv4Addr::new(192, 0, 2, 1), Some(NetIfaceId::from_raw(7))).unwrap();
        raw4_a.connect(Ipv4Addr::new(198, 51, 100, 2), None).unwrap();
        let raw4_b = crate::raw4::Raw4Endpoint::new(144, owner_b,
            Arc::new(crate::bpf_filter::SocketFilter::new()),
            Arc::new(crate::mcast_filter::SocketMcast::new()), Arc::new(SocketError::new()));
        stack.register_raw4(&raw4_a);
        stack.register_raw4(&raw4_b);

        assert_eq!(stack.raw_diag_snapshot_in(ns_a, AF_INET), alloc::vec![RawDiagSnapshot {
            family: AF_INET, protocol: 143,
            local_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            remote_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            ifindex: 7, rqueue: 0, drops: 0,
        }]);
        assert_eq!(stack.raw_diag_snapshot_in(ns_b, AF_INET).len(), 1);

        let local6 = Ipv6Addr::from_segments([0x2001, 0xdb8, 1, 0, 0, 0, 0, 1]);
        let remote6 = Ipv6Addr::from_segments([0x2001, 0xdb8, 2, 0, 0, 0, 0, 2]);
        let raw6 = Arc::new(crate::raw6::Raw6Endpoint::standalone(owner_a, 253));
        raw6.bind(crate::raw6::Raw6Address::new(local6, 0), Some(NetIfaceId::from_raw(8)));
        raw6.connect(crate::raw6::Raw6Address::new(remote6, 0));
        assert_eq!(raw6.receive(crate::raw6::Raw6RxPacket {
            net_ns: ns_a, protocol: 253, src: remote6, dst: local6,
            iface: NetIfaceId::from_raw(8), hop_limit: 64, traffic_class: 0,
            flow_label: 0, hatype: 1, payload: b"queue",
        }), crate::raw6::Raw6RxDisposition::Queued);
        stack.register_raw6(&raw6);
        assert_eq!(stack.raw_diag_snapshot_in(ns_a, AF_INET6), alloc::vec![RawDiagSnapshot {
            family: AF_INET6, protocol: 253, local_ip: IpAddr::V6(local6),
            remote_ip: IpAddr::V6(remote6), ifindex: 8, rqueue: 5, drops: 0,
        }]);
        assert!(stack.raw_diag_snapshot_in(ns_b, AF_INET6).is_empty());

        raw6.close();
        assert!(stack.raw_diag_snapshot_in(ns_a, AF_INET6).is_empty());
    }

    #[test]
    fn udp4_diag_reports_each_group_endpoint_state_tuple_queue_and_ifindex() {
        let stack = NetStack::new();
        let local = Ipv4Addr::new(192, 0, 2, 10);
        let remote = Ipv4Addr::new(198, 51, 100, 20);
        let open = stack.bind_udp_socket(local, 5300, Some(NetIfaceId::from_raw(11)),
            Arc::new(SocketError::new()), reuse(), reuse(),
            Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)), 1000,
            Arc::new(Spinlock::new(None)), Arc::new(crate::bpf_filter::SocketFilter::new()),
            Arc::new(crate::mcast_filter::SocketMcast::new())).unwrap();
        let connected = stack.bind_udp_socket(local, 5300, Some(NetIfaceId::from_raw(12)),
            Arc::new(SocketError::new()), reuse(), reuse(),
            Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)), 1001,
            Arc::new(Spinlock::<Option<(Ipv4Addr, u16)>, StackLockClass>::new(Some((remote, 5400)))),
            Arc::new(crate::bpf_filter::SocketFilter::new()), Arc::new(crate::mcast_filter::SocketMcast::new())).unwrap();
        assert!(open.enqueue((remote, 5400, local, NetIfaceId::from_raw(11), 64, alloc::vec![0; 3])));
        assert!(connected.enqueue((remote, 5400, local, NetIfaceId::from_raw(12), 64, alloc::vec![0; 5])));
        assert!(connected.enqueue((remote, 5400, local, NetIfaceId::from_raw(12), 64, alloc::vec![0; 7])));

        let rows = stack.inet_diag_snapshot(IPPROTO_UDP);
        assert_eq!(rows.len(), 2);
        assert!(rows.contains(&InetDiagSnapshot {
            family: AF_INET, protocol: IPPROTO_UDP, state: TCP_CLOSE,
            local_ip: IpAddr::V4(local), local_port: 5300,
            remote_ip: IpAddr::V4(Ipv4Addr::ANY), remote_port: 0,
            ifindex: 11, rqueue: 3, wqueue: 0,
        }));
        assert!(rows.contains(&InetDiagSnapshot {
            family: AF_INET, protocol: IPPROTO_UDP, state: TCP_ESTABLISHED,
            local_ip: IpAddr::V4(local), local_port: 5300,
            remote_ip: IpAddr::V4(remote), remote_port: 5400,
            ifindex: 12, rqueue: 12, wqueue: 0,
        }));
    }

    #[test]
    fn udp6_diag_reports_each_group_endpoint_state_tuple_queue_and_ifindex() {
        let stack = NetStack::new();
        let local = Ipv6Addr::from_segments([0x2001, 0xdb8, 1, 0, 0, 0, 0, 10]);
        let remote = Ipv6Addr::from_segments([0x2001, 0xdb8, 2, 0, 0, 0, 0, 20]);
        let open = stack.bind_udp6_socket(local, 6300, Some(NetIfaceId::from_raw(21)),
            Arc::new(SocketError::new()), reuse(), reuse(), 1000, dual_stack(),
            Arc::new(Spinlock::new(None)),
            Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
            Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)),
            Arc::new(crate::bpf_filter::SocketFilter::new()),
            Arc::new(crate::mcast_filter::SocketMcast::new())).unwrap();
        let connected = stack.bind_udp6_socket(local, 6300, Some(NetIfaceId::from_raw(22)),
            Arc::new(SocketError::new()), reuse(), reuse(), 1001,
            dual_stack(),
            Arc::new(Spinlock::<Option<(Ipv6Addr, u16)>, StackLockClass>::new(Some((remote, 6400)))),
            Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
            Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)),
            Arc::new(crate::bpf_filter::SocketFilter::new()), Arc::new(crate::mcast_filter::SocketMcast::new())).unwrap();
        assert!(open.enqueue((remote, 6400, local, NetIfaceId::from_raw(21), 64, 0, alloc::vec![0; 4])));
        assert!(connected.enqueue((remote, 6400, local, NetIfaceId::from_raw(22), 64, 0, alloc::vec![0; 6])));
        assert!(connected.enqueue((remote, 6400, local, NetIfaceId::from_raw(22), 64, 0, alloc::vec![0; 8])));

        let rows = stack.inet_diag_snapshot(IPPROTO_UDP);
        assert_eq!(rows.len(), 2);
        assert!(rows.contains(&InetDiagSnapshot {
            family: AF_INET6, protocol: IPPROTO_UDP, state: TCP_CLOSE,
            local_ip: IpAddr::V6(local), local_port: 6300,
            remote_ip: IpAddr::V6(Ipv6Addr::ANY), remote_port: 0,
            ifindex: 21, rqueue: 4, wqueue: 0,
        }));
        assert!(rows.contains(&InetDiagSnapshot {
            family: AF_INET6, protocol: IPPROTO_UDP, state: TCP_ESTABLISHED,
            local_ip: IpAddr::V6(local), local_port: 6300,
            remote_ip: IpAddr::V6(remote), remote_port: 6400,
            ifindex: 22, rqueue: 14, wqueue: 0,
        }));
    }
}
