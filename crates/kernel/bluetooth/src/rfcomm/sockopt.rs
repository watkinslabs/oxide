//! RFCOMM socket options.
//!
//! Two option levels reach the same state. The older `SOL_RFCOMM` link-mode word
//! is a bit set that maps ONTO the security level rather than beside it: the
//! bits are tested in ascending order and each match overwrites the level, so
//! the highest bit present wins and no bit combination can leave the two
//! disagreeing.

use syscall::errno::Errno;

use crate::uapi::bt::{BT_BOUND, BT_CONNECT2, BT_CONNECTED, BT_LISTEN, BT_SECURITY_FIPS,
                      BT_SECURITY_HIGH, BT_SECURITY_LOW, BT_SECURITY_MEDIUM};
use crate::uapi::hci::DEV_CLASS_LEN;
use crate::uapi::rfcomm as u;
use super::sock::RfcommSock;

/// `struct rfcomm_conninfo`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Conninfo {
    pub hci_handle: u16,
    pub dev_class: [u8; DEV_CLASS_LEN],
}

impl Conninfo {
    /// Encode into a `getsockopt` buffer. # C: O(1)
    pub fn to_wire(&self, buf: &mut [u8]) -> bool {
        if buf.len() < u::RFCOMM_CONNINFO_LEN { return false; }
        buf[0..2].copy_from_slice(&self.hci_handle.to_le_bytes());
        buf[2..2 + DEV_CLASS_LEN].copy_from_slice(&self.dev_class);
        true
    }
}

/// Apply an `RFCOMM_LM` word. The FIPS bit alone is refused: a socket cannot ask
/// for a level the older interface has no way to satisfy. # C: O(1)
pub fn set_lm(sk: &mut RfcommSock, opt: u32) -> Result<(), Errno> {
    if opt & u::RFCOMM_LM_FIPS != 0 { return Err(Errno::Einval); }
    if opt & u::RFCOMM_LM_AUTH != 0 { sk.sec_level = BT_SECURITY_LOW; }
    if opt & u::RFCOMM_LM_ENCRYPT != 0 { sk.sec_level = BT_SECURITY_MEDIUM; }
    if opt & u::RFCOMM_LM_SECURE != 0 { sk.sec_level = BT_SECURITY_HIGH; }
    sk.role_switch = opt & u::RFCOMM_LM_MASTER != 0;
    Ok(())
}

/// Reconstruct the `RFCOMM_LM` word from the level. Each level implies every
/// bit below it, so the word read back from a level set through the newer
/// interface names the same requirement. # C: O(1)
pub fn get_lm(sk: &RfcommSock) -> u32 {
    let mut opt = match sk.sec_level {
        BT_SECURITY_LOW => u::RFCOMM_LM_AUTH,
        BT_SECURITY_MEDIUM => u::RFCOMM_LM_AUTH | u::RFCOMM_LM_ENCRYPT,
        BT_SECURITY_HIGH => u::RFCOMM_LM_AUTH | u::RFCOMM_LM_ENCRYPT | u::RFCOMM_LM_SECURE,
        BT_SECURITY_FIPS => u::RFCOMM_LM_AUTH | u::RFCOMM_LM_ENCRYPT | u::RFCOMM_LM_SECURE | u::RFCOMM_LM_FIPS,
        _ => 0,
    };
    if sk.role_switch { opt |= u::RFCOMM_LM_MASTER; }
    opt
}

/// Apply `BT_SECURITY`. RFCOMM tops out below the FIPS level, so asking for it
/// here is a refusal rather than a silent downgrade. # C: O(1)
pub fn set_security(sk: &mut RfcommSock, level: u8) -> Result<(), Errno> {
    if !sk.stream { return Err(Errno::Einval); }
    if level > BT_SECURITY_HIGH { return Err(Errno::Einval); }
    sk.sec_level = level;
    Ok(())
}

/// Read `BT_SECURITY`. The key size reported is zero: RFCOMM does not carry one
/// of its own. # C: O(1)
pub fn get_security(sk: &RfcommSock) -> Result<(u8, u8), Errno> {
    if !sk.stream { return Err(Errno::Einval); }
    Ok((sk.sec_level, 0))
}

/// Apply `BT_DEFER_SETUP`. Deferral only means something before a connection
/// exists to defer, so it is settable in the bound and listening states alone.
/// # C: O(1)
pub fn set_defer_setup(sk: &mut RfcommSock, on: bool) -> Result<(), Errno> {
    if sk.state != BT_BOUND && sk.state != BT_LISTEN { return Err(Errno::Einval); }
    sk.defer_setup = on;
    Ok(())
}

/// Read `BT_DEFER_SETUP`. # C: O(1)
pub fn get_defer_setup(sk: &RfcommSock) -> Result<bool, Errno> {
    if sk.state != BT_BOUND && sk.state != BT_LISTEN { return Err(Errno::Einval); }
    Ok(sk.defer_setup)
}

/// Read `RFCOMM_CONNINFO`. Readable once connected, and on a deferred
/// connection that has not been answered yet — which is the whole point of
/// deferring, since userspace decides on what this reports. # C: O(1)
pub fn get_conninfo(sk: &RfcommSock, dlc_defer_setup: bool, info: Conninfo) -> Result<Conninfo, Errno> {
    if sk.state != BT_CONNECTED && !dlc_defer_setup { return Err(Errno::Enotconn); }
    Ok(info)
}

/// Whether an option number is one this level defines. # C: O(1)
pub fn sol_rfcomm_known(optname: u32) -> bool {
    optname == u::RFCOMM_LM || optname == u::RFCOMM_CONNINFO
}

/// The state a deferred connection sits in while userspace decides. # C: O(1)
pub fn deferred_state() -> u8 { BT_CONNECT2 }
