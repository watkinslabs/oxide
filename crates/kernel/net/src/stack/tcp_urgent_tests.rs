// TCP urgent arrival: the priority readiness it publishes, and the `SIGURG`
// it owes the receiving description's `f_owner`.
//
// Driven against a real `TcpConn` fed real URG segments, so the arrival gate
// the delivery path evaluates is exercised by the same state machine that
// produces it — not by a restatement of it.

use super::*;
use alloc::sync::Arc;
use ::core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use crate::sock::oob_notify::{sk_send_sigurg, urgent_arrived};
use crate::tcp_conn::TcpConn;

static FIRES: AtomicU32 = AtomicU32::new(0);
static SIG: AtomicI32 = AtomicI32::new(0);
static OWNER: AtomicI32 = AtomicI32::new(0);

fn capture(ev: vfs::file::AsyncSignal) {
    SIG.store(ev.sig, Ordering::Release);
    OWNER.store(ev.owner, Ordering::Release);
    FIRES.fetch_add(1, Ordering::Release);
}

fn ep(port: u16) -> Endpoint {
    Endpoint { ip: crate::addr::IpAddr::V4(crate::addr::Ipv4Addr::LOOPBACK), port }
}

fn lo_ip() -> crate::addr::IpAddr {
    crate::addr::IpAddr::V4(crate::addr::Ipv4Addr::LOOPBACK)
}

/// An established server connection. # C: O(1)
fn established(port: u16) -> TcpConn {
    let mut client = TcpConn::new_client(ep(port), ep(80), 1000);
    let mut server = TcpConn::new_listener(ep(80));
    let syn = client.active_open().unwrap();
    let synack = server.input(lo_ip(), lo_ip(), &syn).unwrap().unwrap();
    let ack = client.input(lo_ip(), lo_ip(), &synack).unwrap().unwrap();
    let _ = server.input(lo_ip(), lo_ip(), &ack).unwrap();
    server
}

/// Feed one URG segment and report whether it announced a new urgent pointer —
/// the exact gate the receive path evaluates. # C: O(payload)
fn urg_segment(server: &mut TcpConn, port: u16, seq: u32, payload: &[u8], urg_ptr: u16) -> bool {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut hdr = crate::tcp_hdr::TcpHdr { src_port: port, dst_port: 80, seq, ack: 0,
        data_offset: 5, flags: crate::tcp_hdr::flags::ACK | crate::tcp_hdr::flags::URG,
        window: 65535, checksum: 0, urg_ptr };
    let mut wire = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN + payload.len()];
    hdr.build_into(lo, lo, &mut wire[..crate::tcp_hdr::TCP_HDR_MIN_LEN]);
    wire[crate::tcp_hdr::TCP_HDR_MIN_LEN..].copy_from_slice(payload);
    let pre = server.peek_urgent();
    let _ = server.input_prevalidated(lo_ip(), lo_ip(), &wire).unwrap();
    urgent_arrived(pre, server.peek_urgent())
}

fn entry(conn: TcpConn) -> TcpEntry {
    TcpEntry::new_bound_with_filter_pmtu(conn, Arc::new(crate::SocketError::new()), None,
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)))
}

fn owner_file(owner: i32) -> Arc<vfs::File> {
    let sock = Arc::new(crate::sock::InetSocket::new_unix());
    let inode = crate::sock::make_inet_socket_inode(sock);
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("socket"), inode.clone());
    let file = vfs::File::new_at(inode, dentry, vfs::OpenFlags::O_RDWR, 0, vfs::FileCred::root());
    file.f_setown(owner, vfs::file::owner_type::F_OWNER_PID, 0, 0);
    file
}

// `tcp_poll`: a valid urgent pointer is priority readiness. Without it,
// `select`'s exception set never fires for TCP urgent data and the fasync
// classification calls the arrival ordinary, so it would deliver `SIGIO`.
#[test]
fn a_pending_urgent_pointer_is_priority_readiness() {
    let e = entry(established(5101));
    assert_eq!(e.poll_mask(65_536) & vfs::POLL_PRI, 0, "nothing urgent yet");
    {
        let mut c = e.conn.lock();
        let seq = c.rcv_nxt;
        assert!(urg_segment(&mut c, 5101, seq, b"abc", 2));
    }
    assert_ne!(e.poll_mask(65_536) & vfs::POLL_PRI, 0, "the urgent byte is priority readiness");
    // Consuming it takes the readiness away with it.
    e.conn.lock().take_urgent();
    assert_eq!(e.poll_mask(65_536) & vfs::POLL_PRI, 0);
}

// The pointer is announced once. A retransmit of the same urgent segment must
// not re-signal the owner.
#[test]
fn a_new_urgent_pointer_is_announced_exactly_once() {
    let mut server = established(5102);
    let seq = server.rcv_nxt;
    assert!(urg_segment(&mut server, 5102, seq, b"abc", 2), "first pointer announced");
    // A retransmit of the same segment: already past `rcv_nxt`, no announcement.
    assert!(!urg_segment(&mut server, 5102, seq, b"abc", 2), "retransmit announces nothing");
    // A later segment carrying a new pointer announces again.
    let next = server.rcv_nxt;
    assert!(urg_segment(&mut server, 5102, next, b"xyz", 1), "a new pointer announces");
}

// A plain data segment is not an urgent arrival.
#[test]
fn ordinary_data_announces_no_urgent_pointer() {
    let mut server = established(5103);
    let seq = server.rcv_nxt;
    assert!(!urg_segment(&mut server, 5103, seq, b"abc", 0),
        "URG with a zero pointer carries no urgent byte");
}

// Binding the descriptor to the socket publishes it to the transport too, so
// the socket and its connection cannot name different descriptions.
#[test]
fn binding_the_socket_publishes_the_description_to_its_connection() {
    let e = Arc::new(entry(established(5105)));
    let sock = Arc::new(crate::sock::InetSocket::new_unix());
    *sock.kind.lock() = crate::sock::SockKind::TcpConn(e.clone());
    assert!(e.owner_file().is_none(), "nothing bound yet");
    let file = owner_file(1010);
    sock.set_file(&file);
    let bound = e.owner_file().expect("the connection names the bound description");
    assert!(Arc::ptr_eq(&bound, &file), "and it is the SAME description the socket has");
}

// The description reaches the transport entry, which is what lets the receive
// path — which never holds the socket — signal the owner.
#[test]
fn the_transport_entry_carries_the_owning_description() {
    vfs::file::set_sigio_hook(capture);
    let e = entry(established(5104));
    assert!(e.owner_file().is_none(), "no descriptor bound yet");
    let file = owner_file(31337);
    e.register_file(&file);
    assert!(e.owner_file().is_some(), "the entry names the description");
    FIRES.store(0, Ordering::Release);
    assert!(sk_send_sigurg(e.owner_file()), "an owner is recorded");
    assert_eq!(FIRES.load(Ordering::Acquire), 1);
    assert_eq!(SIG.load(Ordering::Acquire), vfs::file::SIGURG);
    assert_eq!(OWNER.load(Ordering::Acquire), 31337);
    // A closed descriptor leaves nothing to signal, and must not fabricate one.
    drop(file);
    FIRES.store(0, Ordering::Release);
    assert!(!sk_send_sigurg(e.owner_file()));
    assert_eq!(FIRES.load(Ordering::Acquire), 0);
}
