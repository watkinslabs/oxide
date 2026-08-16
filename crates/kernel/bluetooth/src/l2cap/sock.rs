//! The socket-facing surface: the address a channel binds and connects with,
//! whether a service multiplexer may be used and by whom, and the option
//! get/set decisions with the order in which they refuse.
//!
//! The privileged-multiplexer screen takes the capability as a plain operand.
//! Whose capability it is belongs to the caller; whether that capability is
//! enough belongs here.

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use super::chan::{Channel, CONF_STATE2_DEVICE};
use super::codec::{Reader, Writer};
use crate::uapi::bt::{BdAddr, BDADDR_BREDR, BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM, BT_BOUND, BT_CONNECTED, BT_CONNECT2, BT_LISTEN, BT_MODE_BASIC, BT_MODE_ERTM, BT_MODE_EXT_FLOWCTL, BT_MODE_LE_FLOWCTL, BT_MODE_STREAMING, BT_OPEN, BT_SECURITY_FIPS, BT_SECURITY_LOW, AF_BLUETOOTH};
use crate::uapi::l2cap as u;

/// The address an L2CAP socket binds or connects to. Exactly one of the
/// multiplexer and the channel identifier is meaningful; naming both is
/// ambiguous and refused.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct SockAddrL2 {
    pub family: u16,
    pub psm: u16,
    pub bdaddr: BdAddr,
    pub cid: u16,
    pub bdaddr_type: u8,
}

impl SockAddrL2 {
    /// Read an address. A caller may pass a short address, in which case the
    /// bytes it omitted read as zero, exactly as a zeroed buffer would.
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<SockAddrL2> {
        if buf.len() < u::SOCKADDR_L2_FAMILY_OFF + 2 { return None; }
        let mut padded = [0u8; u::SOCKADDR_L2_LEN];
        let n = core::cmp::min(buf.len(), u::SOCKADDR_L2_LEN);
        padded[..n].copy_from_slice(&buf[..n]);
        let mut r = Reader::new(&padded);
        let family = r.le16()?;
        let psm = r.le16()?;
        let bdaddr = BdAddr::from_wire(&padded, u::SOCKADDR_L2_BDADDR_OFF)?;
        let _ = r.bytes(crate::uapi::bt::BDADDR_LEN)?;
        let cid = r.le16()?;
        let bdaddr_type = r.u8()?;
        Some(SockAddrL2 { family, psm, bdaddr, cid, bdaddr_type })
    }

    /// Write the address. # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.le16(self.family);
        w.le16(self.psm);
        w.bytes(self.bdaddr.as_bytes());
        w.le16(self.cid);
        w.u8(self.bdaddr_type);
        let mut v = w.into_vec();
        v.resize(u::SOCKADDR_L2_LEN, 0);
        v
    }

    /// Whether the address type names an LE peer. # C: O(1)
    pub fn is_le(&self) -> bool { self.bdaddr_type == BDADDR_LE_PUBLIC || self.bdaddr_type == BDADDR_LE_RANDOM }
}

/// Whether an address type is one of the three defined. # C: O(1)
pub fn bdaddr_type_valid(t: u8) -> bool { matches!(t, BDADDR_BREDR | BDADDR_LE_PUBLIC | BDADDR_LE_RANDOM) }

/// Whether a BR/EDR multiplexer value is well formed: it must be odd, and the
/// low bit of its upper byte must be clear. # C: O(1)
pub fn bredr_psm_well_formed(psm: u16) -> bool { psm != 0 && psm & u::PSM_BREDR_MASK == u::PSM_BREDR_VALID }

/// Whether an LE multiplexer value is in range. # C: O(1)
pub fn le_psm_well_formed(psm: u16) -> bool { psm != 0 && psm <= u::PSM_LE_DYN_END }

/// Whether a multiplexer may be used to connect out. A well-formed value is
/// enough; the privileged range only restricts who may listen on it.
/// # C: O(1)
pub fn psm_valid(psm: u16, is_le: bool) -> bool {
    if is_le { le_psm_well_formed(psm) } else { bredr_psm_well_formed(psm) }
}

/// Whether a BR/EDR multiplexer may be bound. A malformed value is invalid; a
/// well-formed one below the dynamic range names an assigned service and is
/// reserved to a caller holding the bind-service capability. The malformed
/// check comes first, so an unprivileged caller naming nonsense is told the
/// value is wrong rather than that it lacks a privilege. # C: O(1)
pub fn validate_bredr_psm(psm: u16, cap_net_bind_service: bool) -> Result<(), Errno> {
    if !bredr_psm_well_formed(psm) { return Err(Errno::Einval); }
    if psm < u::PSM_DYN_START && !cap_net_bind_service { return Err(Errno::Eacces); }
    Ok(())
}

/// Whether an LE multiplexer may be bound. # C: O(1)
pub fn validate_le_psm(psm: u16, cap_net_bind_service: bool) -> Result<(), Errno> {
    if psm > u::PSM_LE_DYN_END { return Err(Errno::Einval); }
    if psm < u::PSM_LE_DYN_START && !cap_net_bind_service { return Err(Errno::Eacces); }
    Ok(())
}

/// Whether an address may be bound in the socket's current state. # C: O(1)
pub fn validate_bind(addr: &SockAddrL2, state: u8, cap_net_bind_service: bool) -> Result<(), Errno> {
    if addr.family != AF_BLUETOOTH as u16 { return Err(Errno::Einval); }
    if addr.cid != 0 && addr.psm != 0 { return Err(Errno::Einval); }
    if !bdaddr_type_valid(addr.bdaddr_type) { return Err(Errno::Einval); }
    // Only the attribute channel is reachable from a socket on an LE link; any
    // other fixed identifier belongs to a protocol inside the stack.
    if addr.is_le() && addr.cid != 0 && addr.cid != u::CID_ATT { return Err(Errno::Einval); }
    if state != BT_OPEN { return Err(Errno::Ebadfd); }
    if addr.psm != 0 {
        if addr.bdaddr_type == BDADDR_BREDR { validate_bredr_psm(addr.psm, cap_net_bind_service)?; }
        else { validate_le_psm(addr.psm, cap_net_bind_service)?; }
    }
    Ok(())
}

/// The security level a bound multiplexer implies. Service discovery and the
/// serial-port multiplexer are reachable before pairing, so binding them does
/// not raise the level the way an application multiplexer does. # C: O(1)
pub fn bind_sec_level(chan_type: u8, psm: u16) -> Option<u8> {
    match chan_type {
        u::CHAN_CONN_LESS if psm == u::PSM_3DSP => Some(crate::uapi::bt::BT_SECURITY_SDP),
        u::CHAN_CONN_ORIENTED if psm == u::PSM_SDP || psm == u::PSM_RFCOMM => Some(crate::uapi::bt::BT_SECURITY_SDP),
        u::CHAN_RAW => Some(crate::uapi::bt::BT_SECURITY_SDP),
        _ => None,
    }
}

/// Whether a receive MTU is usable on a channel. The attribute channel has its
/// own floor, below the one every other channel shares; zero means unset and is
/// always allowed. # C: O(1)
pub fn valid_mtu(scid: u16, mtu: u16) -> bool {
    if mtu == 0 { return true; }
    if scid == u::CID_ATT { mtu >= u::LE_MIN_MTU } else { mtu >= u::DEFAULT_MIN_MTU }
}

/// The legacy `L2CAP_OPTIONS` payload.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct L2capOptions {
    pub omtu: u16,
    pub imtu: u16,
    pub flush_to: u16,
    pub mode: u8,
    pub fcs: u8,
    pub max_tx: u8,
    pub txwin_size: u16,
}

impl L2capOptions {
    /// Read the payload, which carries a pad byte before its trailing word.
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<L2capOptions> {
        if buf.len() < u::L2CAP_OPTIONS_LEN { return None; }
        let mut r = Reader::new(buf);
        let omtu = r.le16()?;
        let imtu = r.le16()?;
        let flush_to = r.le16()?;
        let mode = r.u8()?;
        let fcs = r.u8()?;
        let max_tx = r.u8()?;
        let _pad = r.u8()?;
        let txwin_size = r.le16()?;
        Some(L2capOptions { omtu, imtu, flush_to, mode, fcs, max_tx, txwin_size })
    }

    /// Write the payload. # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.le16(self.omtu); w.le16(self.imtu); w.le16(self.flush_to);
        w.u8(self.mode); w.u8(self.fcs); w.u8(self.max_tx); w.u8(0);
        w.le16(self.txwin_size);
        w.into_vec()
    }

    /// The options a channel currently has. # C: O(1)
    pub fn of(chan: &Channel) -> L2capOptions {
        L2capOptions {
            omtu: chan.omtu, imtu: chan.imtu, flush_to: chan.flush_to,
            mode: chan.mode, fcs: chan.fcs, max_tx: chan.max_tx, txwin_size: chan.tx_win,
        }
    }
}

/// Apply the legacy option set. The option only describes BR/EDR channels, only
/// applies before the channel opens, and names a window and an MTU that must be
/// usable — each refusal is checked before anything is written, so a rejected
/// call leaves the channel exactly as it was. # C: O(1)
pub fn set_l2cap_options(chan: &mut Channel, state: u8, opts: &L2capOptions) -> Result<(), Errno> {
    if chan.is_le() { return Err(Errno::Einval); }
    if state == BT_CONNECTED { return Err(Errno::Einval); }
    if opts.txwin_size > u::DEFAULT_EXT_WINDOW { return Err(Errno::Einval); }
    if !valid_mtu(chan.scid, opts.imtu) { return Err(Errno::Einval); }
    match opts.mode {
        u::MODE_BASIC | u::MODE_ERTM | u::MODE_STREAMING => {}
        _ => return Err(Errno::Einval),
    }
    if opts.mode == u::MODE_BASIC { chan.clear_conf(CONF_STATE2_DEVICE); }
    chan.mode = opts.mode;
    chan.imtu = opts.imtu;
    chan.omtu = opts.omtu;
    chan.fcs = opts.fcs;
    chan.max_tx = opts.max_tx;
    chan.tx_win = opts.txwin_size;
    chan.flush_to = opts.flush_to;
    Ok(())
}

/// Read the legacy option set. It describes only the three BR/EDR modes, so a
/// channel running a credit mode has no answer to give. The attribute channel
/// is the exception on an LE link, because its users predate the modern
/// options. # C: O(1)
pub fn get_l2cap_options(chan: &Channel) -> Result<L2capOptions, Errno> {
    if chan.is_le() && chan.scid != u::CID_ATT { return Err(Errno::Einval); }
    match chan.mode {
        u::MODE_BASIC | u::MODE_ERTM | u::MODE_STREAMING => Ok(L2capOptions::of(chan)),
        _ => Err(Errno::Einval),
    }
}

/// Apply the requested transmission mode. Each mode belongs to one transport,
/// and asking for one on the other is refused rather than silently mapped.
/// # C: O(1)
pub fn set_bt_mode(chan: &mut Channel, state: u8, mode: u8) -> Result<(), Errno> {
    if state != BT_BOUND { return Err(Errno::Einval); }
    if chan.chan_type != u::CHAN_CONN_ORIENTED { return Err(Errno::Einval); }
    let le = chan.is_le();
    let m = match mode {
        BT_MODE_BASIC if !le => u::MODE_BASIC,
        BT_MODE_ERTM if !le => u::MODE_ERTM,
        BT_MODE_STREAMING if !le => u::MODE_STREAMING,
        BT_MODE_LE_FLOWCTL if le => u::MODE_LE_FLOWCTL,
        BT_MODE_EXT_FLOWCTL if le => u::MODE_EXT_FLOWCTL,
        _ => return Err(Errno::Einval),
    };
    if m == u::MODE_BASIC { chan.clear_conf(CONF_STATE2_DEVICE); }
    chan.mode = m;
    Ok(())
}

/// Apply a security level. The level must name one of the defined levels and
/// the channel must be one that carries a level at all. # C: O(1)
pub fn set_security(chan: &mut Channel, level: u8) -> Result<(), Errno> {
    match chan.chan_type {
        u::CHAN_CONN_ORIENTED | u::CHAN_FIXED | u::CHAN_RAW => {}
        _ => return Err(Errno::Einval),
    }
    if level < BT_SECURITY_LOW || level > BT_SECURITY_FIPS { return Err(Errno::Einval); }
    chan.sec_level = level;
    Ok(())
}

/// Whether deferred setup may be turned on or off now. It changes how an
/// incoming connection is answered, so it may only be set before the socket can
/// receive one. # C: O(1)
pub fn set_defer_setup(state: u8) -> Result<(), Errno> {
    if state != BT_BOUND && state != BT_LISTEN { return Err(Errno::Einval); }
    Ok(())
}

/// Apply a send MTU. It describes a credit-mode channel and is fixed for the
/// life of a connection. # C: O(1)
pub fn set_sndmtu(chan: &mut Channel, state: u8, mtu: u16) -> Result<(), Errno> {
    if !chan.is_le() { return Err(Errno::Einval); }
    if state == BT_CONNECTED { return Err(Errno::Eisconn); }
    chan.omtu = mtu;
    Ok(())
}

/// What applying a receive MTU implies.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RcvMtu {
    /// The value was stored; nothing goes on the wire.
    Stored,
    /// The channel is open in the enhanced credit mode, which can renegotiate
    /// its receive size, so a reconfiguration must be sent.
    Reconfigure(u16),
}

/// Apply a receive MTU. The plain credit mode fixes it at connect time; the
/// enhanced one can change it on a live channel. # C: O(1)
pub fn set_rcvmtu(chan: &mut Channel, state: u8, mtu: u16) -> Result<RcvMtu, Errno> {
    if !chan.is_le() { return Err(Errno::Einval); }
    if chan.mode == u::MODE_LE_FLOWCTL && state == BT_CONNECTED { return Err(Errno::Eisconn); }
    if chan.mode == u::MODE_EXT_FLOWCTL && state == BT_CONNECTED {
        if mtu < u::ECRED_MIN_MTU { return Err(Errno::Einval); }
        return Ok(RcvMtu::Reconfigure(mtu));
    }
    chan.imtu = mtu;
    Ok(RcvMtu::Stored)
}

/// Whether the connection-info option may be read. It describes a link, so
/// there must be one — an accepted-but-deferred channel counts, because its
/// link exists even though the owner has not accepted it yet. # C: O(1)
pub fn conninfo_readable(state: u8, defer_setup: bool) -> Result<(), Errno> {
    if state == BT_CONNECTED { return Ok(()); }
    if state == BT_CONNECT2 && defer_setup { return Ok(()); }
    Err(Errno::Enotconn)
}

/// Encode the connection-info payload. # C: O(1)
pub fn encode_conninfo(hci_handle: u16, dev_class: [u8; u::DEV_CLASS_LEN]) -> Vec<u8> {
    let mut w = Writer::new();
    w.le16(hci_handle);
    w.bytes(&dev_class);
    let mut v = w.into_vec();
    v.resize(u::L2CAP_CONNINFO_LEN, 0);
    v
}

/// Whether a level of the option namespace is one this protocol answers.
/// # C: O(1)
pub fn level_supported(level: u32) -> Result<(), Errno> {
    if level == crate::uapi::bt::SOL_L2CAP || level == crate::uapi::bt::SOL_BLUETOOTH { Ok(()) }
    else { Err(Errno::Enoprotoopt) }
}

#[cfg(test)]
#[path = "tests/sock.rs"]
mod tests;
