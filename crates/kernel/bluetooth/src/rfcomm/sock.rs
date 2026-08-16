//! The RFCOMM socket surface: what `bind`, `listen`, `connect` and `accept`
//! decide before any frame is built.
//!
//! A listening socket is identified by the pair (server channel, local
//! address), which is why binding channel 0 collides with nothing: it means "no
//! channel yet", and `listen` picks the first free one.

use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::uapi::bt::{BdAddr, AF_BLUETOOTH, BT_BOUND, BT_CLOSED, BT_CONNECT, BT_LISTEN, BT_OPEN, BT_SECURITY_LOW};
use crate::uapi::rfcomm as u;

/// Per-socket RFCOMM state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RfcommSock {
    pub state: u8,
    pub src: BdAddr,
    pub dst: BdAddr,
    pub channel: u8,
    pub sec_level: u8,
    /// Whether the link should be mastered by this end once the DLC is up.
    pub role_switch: bool,
    pub defer_setup: bool,
    /// RFCOMM is stream-only; a socket of any other type is refused by every
    /// operation that would carry data.
    pub stream: bool,
    pub backlog: u32,
}

impl Default for RfcommSock {
    fn default() -> RfcommSock { RfcommSock::new(true) }
}

impl RfcommSock {
    /// A freshly created socket. # C: O(1)
    pub fn new(stream: bool) -> RfcommSock {
        RfcommSock {
            state: BT_OPEN,
            src: BdAddr::default(),
            dst: BdAddr::default(),
            channel: 0,
            sec_level: BT_SECURITY_LOW,
            role_switch: false,
            defer_setup: false,
            stream,
            backlog: 0,
        }
    }

    /// The address this socket reports for itself. # C: O(1)
    pub fn sockname(&self) -> u::SockaddrRc {
        u::SockaddrRc { family: AF_BLUETOOTH as u16, bdaddr: self.src, channel: self.channel }
    }

    /// The address of the peer. # C: O(1)
    pub fn peername(&self) -> u::SockaddrRc {
        u::SockaddrRc { family: AF_BLUETOOTH as u16, bdaddr: self.dst, channel: self.channel }
    }
}

/// The listening sockets one host holds, which is what makes a bind collide and
/// what `listen` searches for a free channel.
#[derive(Default, Debug)]
pub struct Listeners {
    entries: Vec<(u8, BdAddr)>,
}

impl Listeners {
    /// An empty table. # C: O(1)
    pub fn new() -> Listeners { Listeners { entries: Vec::new() } }

    /// Whether a channel is taken on an address. A listener on the any-address
    /// takes the channel for every address, and a request for the any-address
    /// collides with a listener on any one of them. # C: O(n)
    pub fn taken(&self, channel: u8, addr: BdAddr) -> bool {
        self.entries.iter().any(|(c, a)| {
            *c == channel && (*a == addr || a.is_any() || addr.is_any())
        })
    }

    /// Record a listener. # C: O(n)
    pub fn add(&mut self, channel: u8, addr: BdAddr) { self.entries.push((channel, addr)); }

    /// Drop a listener. # C: O(n)
    pub fn remove(&mut self, channel: u8, addr: BdAddr) {
        if let Some(i) = self.entries.iter().position(|e| *e == (channel, addr)) {
            self.entries.remove(i);
        }
    }

    /// Number of listeners. # C: O(1)
    pub fn len(&self) -> usize { self.entries.len() }

    /// Whether nothing is listening. # C: O(1)
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// The first free data channel on an address. # C: O(n)
    pub fn first_free(&self, addr: BdAddr) -> Option<u8> {
        (u::RFCOMM_CHANNEL_MIN..=u::RFCOMM_CHANNEL_MAX).find(|c| !self.taken(*c, addr))
    }
}

/// Bind a socket to a local address and server channel. Channel 0 means the
/// socket is not claiming one yet, so it collides with nothing. # C: O(n)
pub fn bind(sk: &mut RfcommSock, sa: &u::SockaddrRc, listeners: &Listeners) -> Result<(), Errno> {
    if sa.family != AF_BLUETOOTH as u16 { return Err(Errno::Einval); }
    if sk.state != BT_OPEN { return Err(Errno::Ebadfd); }
    if !sk.stream { return Err(Errno::Einval); }
    if sa.channel != 0 && listeners.taken(sa.channel, sa.bdaddr) { return Err(Errno::Eaddrinuse); }
    sk.src = sa.bdaddr;
    sk.channel = sa.channel;
    sk.state = BT_BOUND;
    Ok(())
}

/// Start listening. A socket bound without a channel is given the first free
/// one; when none is free the request fails rather than listening on nothing.
/// # C: O(n)
pub fn listen(sk: &mut RfcommSock, backlog: u32, listeners: &mut Listeners) -> Result<(), Errno> {
    if sk.state != BT_BOUND { return Err(Errno::Ebadfd); }
    if !sk.stream { return Err(Errno::Einval); }
    if sk.channel == 0 {
        let Some(c) = listeners.first_free(sk.src) else { return Err(Errno::Einval); };
        sk.channel = c;
    }
    listeners.add(sk.channel, sk.src);
    sk.backlog = backlog;
    sk.state = BT_LISTEN;
    Ok(())
}

/// Start a connection. The channel must name a data channel, since that is the
/// DLCI the multiplexer will compute from it. # C: O(1)
pub fn connect(sk: &mut RfcommSock, sa: &u::SockaddrRc) -> Result<(), Errno> {
    if sa.family != AF_BLUETOOTH as u16 { return Err(Errno::Einval); }
    if sk.state != BT_OPEN && sk.state != BT_BOUND { return Err(Errno::Ebadfd); }
    if !sk.stream { return Err(Errno::Einval); }
    if !u::channel_valid(sa.channel) { return Err(Errno::Einval); }
    sk.dst = sa.bdaddr;
    sk.channel = sa.channel;
    sk.state = BT_CONNECT;
    Ok(())
}

/// Accept from a listening socket. # C: O(1)
pub fn accept_allowed(sk: &RfcommSock) -> Result<(), Errno> {
    if sk.state != BT_LISTEN { return Err(Errno::Einval); }
    if !sk.stream { return Err(Errno::Einval); }
    Ok(())
}

/// Release a listening socket's claim on its channel. # C: O(n)
pub fn close(sk: &mut RfcommSock, listeners: &mut Listeners) {
    if sk.state == BT_LISTEN { listeners.remove(sk.channel, sk.src); }
    sk.state = BT_CLOSED;
}
