//! Host oracle — socket message paths. Every function here runs the REAL
//! syscall on THIS machine's Linux kernel (`F721` requirement); the fixtures
//! are real loopback sockets, not models.
//!
//! Every `unsafe` block is the same shape: a plain libc FFI call over
//! storage this function itself just built and owns for the call's duration
//! (a live fd, a local `mmsghdr`/`iovec`/buffer array), annotated at its own
//! site rather than repeating that sentence per call.

extern crate std;
use std::vec;
use std::vec::Vec;

use crate::outcome::Outcome;
use crate::oracle::close_raw;

/// A bound UDP receiver and a sender connected to it, on loopback. Both
/// sockets are `O_NONBLOCK` so no case can hang the suite.
pub struct UdpPair {
    pub rx: i32,
    pub tx: i32,
}

impl Drop for UdpPair {
    fn drop(&mut self) { close_raw(self.rx); close_raw(self.tx); }
}

fn loopback_addr(port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr { s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be() },
        sin_zero: [0; 8],
    }
}

/// One UDP pair on loopback, with the receiver already bound. # C: O(1)
pub fn udp_pair() -> UdpPair { udp_pair_with_rcvbuf(0) }

/// A deep receive queue, for cases that must queue more messages than a
/// default buffer holds. `bytes` of 0 leaves the kernel default in place; the
/// kernel doubles what it accepts and caps it at `net.core.rmem_max`, so a
/// case asks for headroom rather than an exact depth and then asserts on what
/// it actually managed to queue. # C: O(1)
pub fn udp_pair_with_rcvbuf(bytes: i32) -> UdpPair {
    // SAFETY: plain socket(2) calls with constant arguments.
    let rx = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0) };
    // SAFETY: plain socket(2) call with constant arguments.
    let tx = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0) };
    assert!(rx >= 0 && tx >= 0, "host udp sockets");
    let mut addr = loopback_addr(0);
    let len = core::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: addr is this frame's sockaddr_in, rx is the fd just opened.
    let rv = unsafe { libc::bind(rx, (&addr as *const libc::sockaddr_in).cast(), len) };
    assert_eq!(rv, 0, "host bind loopback");
    let mut got = len;
    // SAFETY: addr/got are this frame's storage, sized for a sockaddr_in.
    let rv = unsafe { libc::getsockname(rx, (&mut addr as *mut libc::sockaddr_in).cast(), &mut got) };
    assert_eq!(rv, 0, "host getsockname");
    // SAFETY: addr is this frame's bound receiver address, tx is a live fd.
    let rv = unsafe { libc::connect(tx, (&addr as *const libc::sockaddr_in).cast(), len) };
    assert_eq!(rv, 0, "host connect loopback");
    if bytes > 0 {
        let len = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: bytes is this frame's int, rx is the fd just opened.
        let rv = unsafe {
            libc::setsockopt(rx, libc::SOL_SOCKET, libc::SO_RCVBUF,
                (&bytes as *const libc::c_int).cast(), len)
        };
        assert_eq!(rv, 0, "host SO_RCVBUF");
    }
    UdpPair { rx, tx }
}

/// Queue `count` one-byte datagrams on the pair's receiver, waiting until
/// each is visible so a later nonblocking receive sees the whole queue.
/// # C: O(count)
pub fn queue_datagrams(pair: &UdpPair, count: usize) {
    for i in 0..count {
        let byte = [i as u8];
        // SAFETY: byte is this frame's array, tx is a live connected socket.
        let rv = unsafe { libc::send(pair.tx, byte.as_ptr().cast(), 1, 0) };
        assert_eq!(rv, 1, "host queue datagram");
    }
    // Loopback delivery is synchronous, but poll the receiver anyway so the
    // fixture cannot race the case it feeds.
    let mut pfd = libc::pollfd { fd: pair.rx, events: libc::POLLIN, revents: 0 };
    if count > 0 {
        // SAFETY: pfd is this frame's pollfd over a live fd.
        let rv = unsafe { libc::poll(&mut pfd, 1, 1000) };
        assert_eq!(rv, 1, "host queued datagram is readable");
    }
}

/// A connected UDP socket whose peer port has no listener. One send draws an
/// ICMP port-unreachable back, which Linux records as the socket's pending
/// error; the fixture waits for it, so the socket it returns already carries
/// one. Nonblocking, so no case can hang.
pub struct DeadPeer {
    pub fd: i32,
}

impl Drop for DeadPeer {
    fn drop(&mut self) { close_raw(self.fd); }
}

/// # C: O(1)
pub fn udp_dead_peer() -> DeadPeer {
    // Take an ephemeral port and give it straight back, so the address is
    // real and provably unserved rather than assumed idle.
    let vacant = udp_pair();
    let mut addr = loopback_addr(0);
    let mut got = core::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: addr/got are this frame's storage, sized for a sockaddr_in.
    let rv = unsafe { libc::getsockname(vacant.rx, (&mut addr as *mut libc::sockaddr_in).cast(), &mut got) };
    assert_eq!(rv, 0, "host getsockname");
    drop(vacant);
    // SAFETY: plain socket(2) call with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0) };
    assert!(fd >= 0, "host udp socket");
    let len = core::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: addr is this frame's sockaddr_in, fd is the socket just opened.
    let rv = unsafe { libc::connect(fd, (&addr as *const libc::sockaddr_in).cast(), len) };
    assert_eq!(rv, 0, "host connect to a vacant port");
    let byte = [0u8];
    // SAFETY: byte is this frame's array, fd is a live connected socket.
    let rv = unsafe { libc::send(fd, byte.as_ptr().cast(), 1, 0) };
    assert_eq!(rv, 1, "host send to a vacant port");
    let mut pfd = libc::pollfd { fd, events: libc::POLLERR, revents: 0 };
    // SAFETY: pfd is this frame's pollfd over a live fd.
    let rv = unsafe { libc::poll(&mut pfd, 1, 2000) };
    assert_eq!(rv, 1, "host icmp port-unreachable reaches the socket");
    assert_ne!(pfd.revents & libc::POLLERR, 0, "the socket carries a pending error");
    DeadPeer { fd }
}

/// Drain a receiver one message at a time with plain `recv(2)`, returning how
/// many datagrams were really queued. Deliberately does NOT use `recvmmsg`:
/// a case that measures its own fixture with the call under test proves
/// nothing. # C: O(queued)
pub fn drain_count(pair: &UdpPair) -> usize {
    let mut buf = [0u8; 64];
    let mut n = 0usize;
    loop {
        // SAFETY: buf is this frame's array, rx is a live nonblocking socket.
        let rv = unsafe { libc::recv(pair.rx, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if rv < 0 { return n; }
        n += 1;
    }
}

/// One `recvmmsg` call's arguments. `bad_iov_at` gives that entry an
/// unmapped `msg_iov` pointer, the cheapest way to fail one entry of a batch
/// mid-flight.
pub struct RecvBatch {
    pub vlen: u32,
    pub flags: i32,
    pub timeout: Option<(i64, i64)>,
    pub bad_iov_at: Option<u32>,
}

impl RecvBatch {
    pub fn new(vlen: u32, flags: i32) -> Self {
        RecvBatch { vlen, flags, timeout: None, bad_iov_at: None }
    }
}

/// An address no mapping can cover, for the deliberate `EFAULT` entry.
const UNMAPPED: usize = 0x1000;

/// `recvmmsg(2)` on the host, over `vlen` freshly built entries. # C: O(vlen)
pub fn recvmmsg(fd: i32, batch: &RecvBatch) -> Outcome {
    let n = batch.vlen.max(1) as usize;
    let mut bufs: Vec<[u8; 64]> = vec![[0u8; 64]; n];
    let mut iov: Vec<libc::iovec> = Vec::with_capacity(n);
    for buf in bufs.iter_mut() {
        iov.push(libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() });
    }
    // SAFETY: mmsghdr is a plain POD header array this frame owns; every
    // pointer field is filled in below before the call reads it.
    let mut msgs: Vec<libc::mmsghdr> = unsafe { vec![core::mem::zeroed(); n] };
    for (i, msg) in msgs.iter_mut().enumerate() {
        msg.msg_hdr.msg_iov = if batch.bad_iov_at == Some(i as u32) {
            UNMAPPED as *mut libc::iovec
        } else {
            &mut iov[i] as *mut libc::iovec
        };
        msg.msg_hdr.msg_iovlen = 1;
    }
    let mut ts = batch.timeout.map(|(sec, nsec)| libc::timespec { tv_sec: sec, tv_nsec: nsec });
    let ts_ptr = ts.as_mut().map_or(core::ptr::null_mut(), |t| t as *mut libc::timespec);
    // SAFETY: msgs/iov/bufs/ts are this frame's storage, live for the call.
    let rv = unsafe {
        libc::recvmmsg(fd, msgs.as_mut_ptr(), batch.vlen as libc::c_uint, batch.flags, ts_ptr)
    };
    Outcome::from_host(rv as i64)
}

/// `recvmmsg(2)` with a supplied timeout, reporting whether the kernel wrote
/// the remaining time BACK over the caller's timespec. `batch.timeout` must
/// be set. # C: O(vlen)
pub fn recvmmsg_timeout_writeback(fd: i32, batch: &RecvBatch) -> (Outcome, bool) {
    let supplied = batch.timeout.expect("a writeback case supplies a timeout");
    let n = batch.vlen.max(1) as usize;
    let mut bufs: Vec<[u8; 64]> = vec![[0u8; 64]; n];
    let mut iov: Vec<libc::iovec> = Vec::with_capacity(n);
    for buf in bufs.iter_mut() {
        iov.push(libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() });
    }
    // SAFETY: mmsghdr is a plain POD header array this frame owns; every
    // pointer field is filled in below before the call reads it.
    let mut msgs: Vec<libc::mmsghdr> = unsafe { vec![core::mem::zeroed(); n] };
    for (i, msg) in msgs.iter_mut().enumerate() {
        msg.msg_hdr.msg_iov = &mut iov[i] as *mut libc::iovec;
        msg.msg_hdr.msg_iovlen = 1;
    }
    let mut ts = libc::timespec { tv_sec: supplied.0, tv_nsec: supplied.1 };
    // SAFETY: msgs/iov/bufs/ts are this frame's storage, live for the call.
    let rv = unsafe {
        libc::recvmmsg(fd, msgs.as_mut_ptr(), batch.vlen as libc::c_uint, batch.flags, &mut ts)
    };
    (Outcome::from_host(rv as i64), (ts.tv_sec, ts.tv_nsec) != supplied)
}

/// `getsockopt(SO_ERROR)` — reads AND clears the socket's pending error, the
/// way a caller collects what a partial batch latched. # C: O(1)
pub fn so_error(fd: i32) -> i32 {
    let mut err: libc::c_int = 0;
    let mut len = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: err/len are this frame's storage, sized for SO_ERROR's int.
    let rv = unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR,
            (&mut err as *mut libc::c_int).cast(), &mut len)
    };
    assert_eq!(rv, 0, "host getsockopt(SO_ERROR)");
    err
}

/// `sendmmsg(2)` of `vlen` one-byte datagrams from an unconnected UDP socket
/// to a loopback port with no listener — nothing queues, so the count the
/// host reports is the batch bound itself. # C: O(vlen)
pub fn sendmmsg_discard(vlen: u32) -> Outcome {
    // SAFETY: plain socket(2) call with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0) };
    assert!(fd >= 0, "host udp socket");
    let addr = loopback_addr(DISCARD_PORT);
    let n = vlen as usize;
    let mut payload = [0u8; 1];
    let mut iov: Vec<libc::iovec> = vec![
        libc::iovec { iov_base: payload.as_mut_ptr().cast(), iov_len: 1 }; n];
    // SAFETY: mmsghdr is a plain POD header array this frame owns; every
    // pointer field is filled in below before the call reads it.
    let mut msgs: Vec<libc::mmsghdr> = unsafe { vec![core::mem::zeroed(); n] };
    for (i, msg) in msgs.iter_mut().enumerate() {
        msg.msg_hdr.msg_name = (&addr as *const libc::sockaddr_in as *mut libc::c_void).cast();
        msg.msg_hdr.msg_namelen = core::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_hdr.msg_iov = &mut iov[i] as *mut libc::iovec;
        msg.msg_hdr.msg_iovlen = 1;
    }
    // SAFETY: msgs/iov/payload/addr are this frame's storage, live for the call.
    let rv = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), vlen as libc::c_uint, 0) };
    let out = Outcome::from_host(rv as i64);
    close_raw(fd);
    out
}

/// RFC 863 discard port — nothing on this machine listens there, and an
/// unconnected sender is never told about the resulting ICMP.
const DISCARD_PORT: u16 = 9;
