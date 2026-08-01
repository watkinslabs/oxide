// The level-17 set/get decision tables: which option numbers exist, what
// value window each accepts, and which errno an out-of-table request gets.

use core::sync::atomic::Ordering;

use crate::NetError;

use super::state::UdpOpts;
use super::uapi::*;

/// Transmit-side effect a completed `setsockopt` implies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetEffect {
    None,
    /// Clearing `UDP_CORK` pushes whatever the cork accumulated.
    Push,
}

/// Every level-17 option is an `int`, so the operand is imported once by the
/// caller and validated here. An option number outside the table is
/// `ENOPROTOOPT`, including the two numbers UDP-Lite reserved. # C: O(1)
pub fn set(opts: &UdpOpts, optname: u64, val: i32) -> Result<SetEffect, NetError> {
    let boolean = i32::from(val != 0);
    match optname {
        UDP_CORK => {
            opts.cork.store(boolean, Ordering::Release);
            return Ok(if boolean == 0 { SetEffect::Push } else { SetEffect::None });
        }
        UDP_ENCAP => match val {
            UDP_ENCAP_NONE | UDP_ENCAP_ESPINUDP | UDP_ENCAP_L2TPINUDP =>
                opts.encap_type.store(val, Ordering::Release),
            _ => return Err(NetError::Enoprotoopt),
        },
        UDP_NO_CHECK6_TX => opts.no_check6_tx.store(boolean, Ordering::Release),
        UDP_NO_CHECK6_RX => opts.no_check6_rx.store(boolean, Ordering::Release),
        UDP_SEGMENT => {
            if !(0..=UDP_SEGMENT_MAX).contains(&val) { return Err(NetError::Einval); }
            opts.gso_size.store(val, Ordering::Release);
        }
        UDP_GRO => opts.gro.store(boolean, Ordering::Release),
        _ => return Err(NetError::Enoprotoopt),
    }
    Ok(SetEffect::None)
}

/// The `int` each readable level-17 option answers with. # C: O(1)
pub fn get(opts: &UdpOpts, optname: u64) -> Result<i32, NetError> {
    Ok(match optname {
        UDP_CORK => opts.cork.load(Ordering::Acquire),
        UDP_ENCAP => opts.encap_type.load(Ordering::Acquire),
        UDP_NO_CHECK6_TX => opts.no_check6_tx.load(Ordering::Acquire),
        UDP_NO_CHECK6_RX => opts.no_check6_rx.load(Ordering::Acquire),
        UDP_SEGMENT => opts.gso_size.load(Ordering::Acquire),
        UDP_GRO => opts.gro.load(Ordering::Acquire),
        _ => return Err(NetError::Enoprotoopt),
    })
}
