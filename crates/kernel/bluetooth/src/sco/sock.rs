//! The SCO socket surface and its options.
//!
//! Each option has a state window as much as a value: the voice setting and the
//! codec may only move while there is no link to disturb, and the link's
//! properties may only be read once there is a link — or, on a deferred
//! connection, while userspace is deciding whether to have one, which is
//! exactly when it needs to see them.

use syscall::errno::Errno;

use crate::uapi::bt::{BdAddr, AF_BLUETOOTH, BT_BOUND, BT_CLOSED, BT_CONNECT, BT_CONNECT2,
                      BT_CONNECTED, BT_LISTEN, BT_OPEN};
use crate::uapi::hci::DEV_CLASS_LEN;
use crate::uapi::sco as u;
use super::conn;

/// Per-socket SCO state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ScoSock {
    pub state: u8,
    pub src: BdAddr,
    pub dst: BdAddr,
    /// Voice setting: the air coding and sample format the link asks for.
    pub setting: u16,
    pub codec: u::BtCodec,
    pub defer_setup: bool,
    /// Whether a received packet carries its reception status as ancillary
    /// data.
    pub pkt_status: bool,
    /// Payload ceiling of the link, once there is one.
    pub mtu: u16,
}

impl Default for ScoSock {
    fn default() -> ScoSock { ScoSock::new() }
}

impl ScoSock {
    /// A freshly created socket: the variable-slope coding at sixteen bits,
    /// which is what a headset expects before anything negotiates. # C: O(1)
    pub fn new() -> ScoSock {
        ScoSock {
            state: BT_OPEN,
            src: BdAddr::default(),
            dst: BdAddr::default(),
            setting: conn::default_setting(),
            codec: conn::default_codec(conn::default_setting()),
            defer_setup: false,
            pkt_status: false,
            mtu: u::SCO_DEFAULT_MTU,
        }
    }

    /// The address this socket reports for itself. # C: O(1)
    pub fn sockname(&self) -> u::SockaddrSco {
        u::SockaddrSco { family: AF_BLUETOOTH as u16, bdaddr: self.src }
    }

    /// The address of the peer. # C: O(1)
    pub fn peername(&self) -> u::SockaddrSco {
        u::SockaddrSco { family: AF_BLUETOOTH as u16, bdaddr: self.dst }
    }

    /// Whether the link's properties may be read: connected, or deferred and
    /// still waiting on the decision. # C: O(1)
    pub fn link_readable(&self) -> bool {
        self.state == BT_CONNECTED || (self.state == BT_CONNECT2 && self.defer_setup)
    }
}

/// Bind to a local address. # C: O(1)
pub fn bind(sk: &mut ScoSock, sa: &u::SockaddrSco) -> Result<(), Errno> {
    if sa.family != AF_BLUETOOTH as u16 { return Err(Errno::Einval); }
    if sk.state != BT_OPEN { return Err(Errno::Ebadfd); }
    sk.src = sa.bdaddr;
    sk.state = BT_BOUND;
    Ok(())
}

/// Start a connection. # C: O(1)
pub fn connect(sk: &mut ScoSock, sa: &u::SockaddrSco) -> Result<(), Errno> {
    if sa.family != AF_BLUETOOTH as u16 { return Err(Errno::Einval); }
    if sk.state != BT_OPEN && sk.state != BT_BOUND { return Err(Errno::Ebadfd); }
    sk.dst = sa.bdaddr;
    sk.state = BT_CONNECT;
    Ok(())
}

/// Start listening. # C: O(1)
pub fn listen(sk: &mut ScoSock) -> Result<(), Errno> {
    if sk.state != BT_BOUND { return Err(Errno::Ebadfd); }
    sk.state = BT_LISTEN;
    Ok(())
}

/// Close. # C: O(1)
pub fn close(sk: &mut ScoSock) { sk.state = BT_CLOSED; }

/// Apply `BT_VOICE`. Settable only while no link exists to disturb, or while a
/// deferred one is still waiting to be answered — after that the air coding is
/// already negotiated. Selecting transparent coding selects the transparent
/// codec with it, so the two cannot disagree. # C: O(1)
pub fn set_voice(sk: &mut ScoSock, setting: u16) -> Result<(), Errno> {
    if sk.state != BT_OPEN && sk.state != BT_BOUND && sk.state != BT_CONNECT2 {
        return Err(Errno::Einval);
    }
    sk.setting = setting;
    sk.codec = conn::default_codec(setting);
    Ok(())
}

/// Read `BT_VOICE`, which is readable in any state. # C: O(1)
pub fn get_voice(sk: &ScoSock) -> u16 { sk.setting }

/// Apply `BT_DEFER_SETUP`. # C: O(1)
pub fn set_defer_setup(sk: &mut ScoSock, on: bool) -> Result<(), Errno> {
    if sk.state != BT_BOUND && sk.state != BT_LISTEN { return Err(Errno::Einval); }
    sk.defer_setup = on;
    Ok(())
}

/// Read `BT_DEFER_SETUP`. # C: O(1)
pub fn get_defer_setup(sk: &ScoSock) -> Result<bool, Errno> {
    if sk.state != BT_BOUND && sk.state != BT_LISTEN { return Err(Errno::Einval); }
    Ok(sk.defer_setup)
}

/// Apply `BT_PKT_STATUS`, which is settable in any state: it changes what a
/// later read reports, not the link. # C: O(1)
pub fn set_pkt_status(sk: &mut ScoSock, on: bool) { sk.pkt_status = on; }

/// Read `BT_PKT_STATUS`. # C: O(1)
pub fn get_pkt_status(sk: &ScoSock) -> bool { sk.pkt_status }

/// Apply `BT_CODEC`. The option carries exactly one codec; a list of any other
/// length is refused rather than truncated. # C: O(1)
pub fn set_codec(sk: &mut ScoSock, num_codecs: u8, first: Option<u::BtCodec>) -> Result<(), Errno> {
    if sk.state != BT_OPEN && sk.state != BT_BOUND && sk.state != BT_CONNECT2 {
        return Err(Errno::Einval);
    }
    let Some(c) = first else { return Err(Errno::Einval); };
    if num_codecs != 1 { return Err(Errno::Einval); }
    sk.codec = c;
    Ok(())
}

/// Read `SCO_OPTIONS`: the link's payload ceiling. # C: O(1)
pub fn get_options(sk: &ScoSock) -> Result<u16, Errno> {
    if !sk.link_readable() { return Err(Errno::Enotconn); }
    Ok(sk.mtu)
}

/// `struct sco_conninfo`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Conninfo {
    pub hci_handle: u16,
    pub dev_class: [u8; DEV_CLASS_LEN],
}

impl Conninfo {
    /// Encode into a `getsockopt` buffer. # C: O(1)
    pub fn to_wire(&self, buf: &mut [u8]) -> bool {
        if buf.len() < u::SCO_CONNINFO_LEN { return false; }
        buf[..u::SCO_CONNINFO_LEN].fill(0);
        buf[0..2].copy_from_slice(&self.hci_handle.to_le_bytes());
        buf[u::SCO_CONNINFO_CLASS_OFF..u::SCO_CONNINFO_CLASS_OFF + DEV_CLASS_LEN]
            .copy_from_slice(&self.dev_class);
        true
    }
}

/// Read `SCO_CONNINFO`. # C: O(1)
pub fn get_conninfo(sk: &ScoSock, info: Conninfo) -> Result<Conninfo, Errno> {
    if !sk.link_readable() { return Err(Errno::Enotconn); }
    Ok(info)
}

/// Read `BT_SNDMTU` or `BT_RCVMTU`, which report the same ceiling and demand a
/// live link rather than a deferred one. # C: O(1)
pub fn get_mtu(sk: &ScoSock) -> Result<u16, Errno> {
    if sk.state != BT_CONNECTED { return Err(Errno::Enotconn); }
    Ok(sk.mtu)
}
