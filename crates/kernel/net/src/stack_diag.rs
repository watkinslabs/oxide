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
    /// Snapshot TCP listeners, TCP connections, and UDP bindings for
    /// NETLINK_SOCK_DIAG inet_diag dumps. # C: O(TCP + UDP sockets)
    pub fn inet_diag_snapshot(&self, protocol: u8) -> Vec<InetDiagSnapshot> {
        let mut out = Vec::new();
        match protocol {
            IPPROTO_TCP => {
                for entries in self.tcp_listens_map().lock().values() {
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
                            ifindex: listener.bound_ifindex.load(Ordering::Acquire),
                            rqueue: listener.accept_q.lock().len() as u32,
                            wqueue: 0,
                        });
                    }
                }
                for entry in self.tcp_conns_map().lock().values() {
                    let conn = entry.conn.lock();
                    out.push(InetDiagSnapshot {
                        family: family(conn.local.ip),
                        protocol,
                        state: tcp_diag_state(conn.state),
                        local_ip: conn.local.ip,
                        local_port: conn.local.port,
                        remote_ip: conn.remote.ip,
                        remote_port: conn.remote.port,
                        ifindex: entry.bound_ifindex.load(Ordering::Acquire),
                        rqueue: conn.recv_buf.len() as u32,
                        wqueue: conn.send_buf.len() as u32,
                    });
                }
            }
            IPPROTO_UDP => {
                for q in self.udp_map().lock().values() {
                    out.push(InetDiagSnapshot {
                        family: AF_INET,
                        protocol,
                        state: TCP_CLOSE,
                        local_ip: IpAddr::V4(q.bound_ip),
                        local_port: q.bound_port,
                        remote_ip: IpAddr::V4(Ipv4Addr::ANY),
                        remote_port: 0,
                        ifindex: q.bound_ifindex.load(Ordering::Acquire),
                        rqueue: q.q.lock().iter().map(|(_, _, _, _, p)| p.len() as u32).sum(),
                        wqueue: 0,
                    });
                }
                for q in self.udp6_map().lock().values() {
                    out.push(InetDiagSnapshot {
                        family: AF_INET6,
                        protocol,
                        state: TCP_CLOSE,
                        local_ip: IpAddr::V6(q.bound_ip),
                        local_port: q.bound_port,
                        remote_ip: IpAddr::V6(Ipv6Addr::ANY),
                        remote_port: 0,
                        ifindex: q.bound_ifindex.load(Ordering::Acquire),
                        rqueue: q.q.lock().iter().map(|(_, _, p)| p.len() as u32).sum(),
                        wqueue: 0,
                    });
                }
            }
            _ => {}
        }
        out
    }
}
