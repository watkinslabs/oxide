// Passive fast open end to end, over real segments on the delivery path: the
// cookie a client asks for arrives on the SYN-ACK, presenting it back puts the
// SYN's data straight into an accepted connection, and every way of getting it
// wrong leaves an ordinary handshake behind.
//
// The ladder itself is unit-tested in `tcp_fastopen/server_tests.rs`; what is
// asserted here is that the passive-open path is wired to it — that the
// decision reaches the SYN-ACK's option area, that the payload is delivered
// before the acknowledgement covering it is built, and that the accept queue
// and the fast-open bound are accounted the way the decision said.

use super::*;
use crate::tcp_conn::fastopen::{Cookie, FastOpen};
use crate::tcp_conn::syn_opts::SynOptions;
use crate::tcp_fastopen::{TFO_DEFAULT, TFO_SERVER_ENABLE};
use crate::tcp_state::TcpState;
use ::core::sync::atomic::Ordering;

const SERVER: Ipv4Addr = Ipv4Addr::LOOPBACK;
const CLIENT_SEQ: u32 = 0x2000_0000;

/// A listener with passive fast open enabled, a bound of `max_qlen`, and a
/// drawn namespace key.
fn fixture(stack: &NetStack, port: u16, max_qlen: i32)
    -> (NetIfaceId, Arc<TcpListenEntry>)
{
    let (iface, _lo_dev) = stack.register_loopback();
    let listener = stack.tcp_listen(SERVER, port, true).expect("listen");
    let namespace = &listener.owner.net_namespace;
    crate::net_ns::materialize_state(namespace);
    crate::sysctl::set_value(namespace, crate::net_ns::NetSysctlKey::TcpFastopen,
        (TFO_DEFAULT | TFO_SERVER_ENABLE) as i64).expect("enable the server half");
    crate::tcp_fastopen::init_key_once(namespace);
    listener.fastopen.set_max_qlen(max_qlen);
    (iface, listener)
}

/// Deliver one SYN carrying `option` and `payload`. Returns the child it
/// opened, if the SYN reached the listener at all.
fn syn(stack: &NetStack, iface: NetIfaceId, port: u16, client_port: u16,
       option: Option<Cookie>, payload: &[u8]) -> Option<Server>
{
    syn_flags(stack, iface, port, client_port, option, payload, crate::tcp_hdr::flags::SYN)
}

/// Deliver one SYN with an explicit control-flag set. # C: O(segment)
fn syn_flags(stack: &NetStack, iface: NetIfaceId, port: u16, client_port: u16,
             option: Option<Cookie>, payload: &[u8], flags: u8) -> Option<Server>
{
    let opts = SynOptions { mss: Some(1460), fastopen: option, ..SynOptions::default() };
    let opt_len = opts.encoded_len();
    let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN + opt_len + payload.len()];
    opts.encode(&mut buf[crate::tcp_hdr::TCP_HDR_MIN_LEN..]);
    let at = crate::tcp_hdr::TCP_HDR_MIN_LEN + opt_len;
    buf[at..].copy_from_slice(payload);
    let mut hdr = crate::tcp_hdr::TcpHdr {
        src_port: client_port, dst_port: port,
        seq: CLIENT_SEQ, ack: 0, data_offset: opts.data_offset(),
        flags,
        window: 65_535, checksum: 0, urg_ptr: 0,
    };
    hdr.build_into(SERVER, SERVER, &mut buf);
    let peer = IpAddr::V4(SERVER);
    stack.deliver_tcp_packet(0, iface, peer, IpAddr::V4(SERVER), &buf, &buf)
        .expect("deliver SYN");
    let key = TcpKey {
        local_ip: IpAddr::V4(SERVER), local_port: port,
        remote_ip: peer, remote_port: client_port,
    };
    Server::of(stack.inet_tables(0).tcp_conns.lock().get(&key).cloned())
}

/// The listener side of a delivered SYN. An ordinary passive open leaves a
/// half-open request; a fast open whose data was taken leaves a connection,
/// because the program is handed that one at the SYN.
#[derive(Clone)]
enum Server { Req(Arc<crate::stack::TcpReq>), Sock(Arc<TcpEntry>) }

impl Server {
    fn of(slot: Option<crate::stack::TcpSlot>) -> Option<Self> {
        Some(match slot? {
            crate::stack::TcpSlot::Req(req) => Self::Req(req),
            crate::stack::TcpSlot::Sock(entry) => Self::Sock(entry),
        })
    }

    /// The connection this side holds, or the one the request would open.
    fn with_conn<R>(&self, read: impl FnOnce(&TcpConn) -> R) -> R {
        match self {
            Self::Req(req) => read(&req.open_conn()),
            Self::Sock(entry) => read(&entry.conn.lock()),
        }
    }

    fn state(&self) -> TcpState { self.with_conn(|c| c.state) }

    /// Whether the accepted connection is this one.
    fn is(&self, accepted: &Arc<TcpEntry>) -> bool {
        matches!(self, Self::Sock(entry) if Arc::ptr_eq(entry, accepted))
    }

    /// The SYN-ACK bytes this side answered with — rebuilt from the request's
    /// recorded negotiation, or read back off the queue holding it.
    fn synack(&self) -> Vec<u8> {
        match self {
            Self::Req(req) => req.synack(),
            Self::Sock(entry) => {
                let c = entry.conn.lock();
                let front = c.retx_q.front().expect("the SYN-ACK is held for retransmit");
                c.build_retx(front)
            }
        }
    }
}

/// The fast-open option the SYN-ACK carried — the same bytes that went to the
/// wire.
fn synack_option(server: &Server) -> FastOpen {
    crate::tcp_conn::fastopen::parse(&server.synack(), true)
}

/// The acknowledgement number the SYN-ACK carries.
fn synack_ack(server: &Server) -> u32 {
    crate::tcp_hdr::parse_prevalidated(&server.synack())
        .expect("a well-formed SYN-ACK").ack
}

/// Ask for a cookie and read the one the SYN-ACK offers.
fn obtain_cookie(stack: &NetStack, iface: NetIfaceId, port: u16, client_port: u16) -> Cookie {
    let server = syn(stack, iface, port, client_port, Some(Cookie::request(false)), b"")
        .expect("the SYN opened a request");
    let FastOpen::Cookie(c) = synack_option(&server)
        else { unreachable!("a cookie request is answered on the SYN-ACK") };
    c
}


#[path = "tests/server.rs"]
mod server;
#[path = "tests/client.rs"]
mod client;
