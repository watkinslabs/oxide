//! The voice data path.
//!
//! A synchronous packet carries no sequencing and no retransmission: what
//! arrives is played and what is lost is gone. The only thing a receiver learns
//! beyond the samples is the reception status the controller stamps on the
//! packet, which a socket asks for and which travels as ancillary data.

use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::uapi::bt::{BT_CONNECTED, BT_SCM_PKT_STATUS};
use crate::uapi::hci::HCI_MAX_SCO_SIZE;
use super::link::ScoTx;
use super::sock::ScoSock;

/// Reception status the controller reports per packet.
pub const SCO_PKT_STATUS_OK:         u8 = 0x00;
pub const SCO_PKT_STATUS_INVALID:    u8 = 0x01;
pub const SCO_PKT_STATUS_NO_DATA:    u8 = 0x02;
pub const SCO_PKT_STATUS_PARTIAL:    u8 = 0x03;

/// One packet handed to a reader, with the ancillary status when the socket
/// asked for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RxPacket {
    pub data: Vec<u8>,
    /// The ancillary control message: the type and its one-byte value, present
    /// only when the socket asked for it.
    pub cmsg: Option<(u32, u8)>,
}

/// Send voice. A packet larger than a synchronous frame can carry is refused
/// rather than split: splitting voice inserts a gap the far end plays. # C: O(n)
pub fn send<T: ScoTx>(sk: &ScoSock, handle: u16, data: &[u8], tx: &mut T) -> Result<usize, Errno> {
    if sk.state != BT_CONNECTED { return Err(Errno::Enotconn); }
    if data.len() > HCI_MAX_SCO_SIZE { return Err(Errno::Einval); }
    if data.len() > sk.mtu as usize { return Err(Errno::Einval); }
    tx.send_data(handle, data)?;
    Ok(data.len())
}

/// Take a received packet for a reader, attaching the reception status when the
/// socket asked for it. An empty packet is dropped rather than delivered: a zero
/// length read is how a stream socket signals end of file, which a voice link
/// never means. # C: O(n)
pub fn recv(sk: &ScoSock, data: &[u8], pkt_status: u8) -> Option<RxPacket> {
    if data.is_empty() { return None; }
    let cmsg = if sk.pkt_status { Some((BT_SCM_PKT_STATUS, pkt_status)) } else { None };
    Some(RxPacket { data: data.to_vec(), cmsg })
}

/// The reception status carried by a synchronous packet's header flags — the
/// low two bits of the nibble above the handle. # C: O(1)
pub fn status_of(flags: u16) -> u8 { (flags & 0x03) as u8 }
