//! Modem-line mapping between the V.24 signal byte and the terminal's modem
//! bits.
//!
//! The mapping is not symmetric and cannot be: the peer reports four inputs,
//! this end drives two outputs. Ready-to-communicate and ready-to-receive
//! travel one way as DSR and CTS and the other way as DTR and RTS, so the same
//! two V.24 bits appear on both sides of the translation with different names.

use crate::uapi::rfcomm as u;

/// Terminal modem-status bits, as a `TIOCMGET` reports them.
pub const TIOCM_LE:  u32 = 0x001;
pub const TIOCM_DTR: u32 = 0x002;
pub const TIOCM_RTS: u32 = 0x004;
pub const TIOCM_CTS: u32 = 0x020;
pub const TIOCM_CAR: u32 = 0x040;
pub const TIOCM_RNG: u32 = 0x080;
pub const TIOCM_DSR: u32 = 0x100;
/// Carrier detect and ring indicator, under the names a driver uses.
pub const TIOCM_CD: u32 = TIOCM_CAR;
pub const TIOCM_RI: u32 = TIOCM_RNG;

/// Translate the peer's signals into the modem bits a reader of the terminal
/// sees. # C: O(1)
pub fn v24_to_tiocm(v24_sig: u8) -> u32 {
    let mut m = 0;
    if v24_sig & u::RFCOMM_V24_RTC != 0 { m |= TIOCM_DSR; }
    if v24_sig & u::RFCOMM_V24_RTR != 0 { m |= TIOCM_CTS; }
    if v24_sig & u::RFCOMM_V24_IC  != 0 { m |= TIOCM_RI; }
    if v24_sig & u::RFCOMM_V24_DV  != 0 { m |= TIOCM_CD; }
    m
}

/// Whether a new signal byte drops a carrier the port was holding, which is the
/// condition that hangs the terminal up. # C: O(1)
pub fn carrier_dropped(prev_tiocm: u32, v24_sig: u8) -> bool {
    prev_tiocm & TIOCM_CD != 0 && v24_sig & u::RFCOMM_V24_DV == 0
}

/// Apply a `TIOCMSET`-style set/clear pair to this end's signal byte. The two
/// outputs this end drives are the only bits that move; the peer's inputs are
/// not writable from here. # C: O(1)
pub fn apply_tiocm(v24_sig: u8, set: u32, clear: u32) -> u8 {
    let mut v = v24_sig;
    if set & TIOCM_DTR != 0 { v |= u::RFCOMM_V24_RTC; }
    if set & TIOCM_RTS != 0 { v |= u::RFCOMM_V24_RTR; }
    if clear & TIOCM_DTR != 0 { v &= !u::RFCOMM_V24_RTC; }
    if clear & TIOCM_RTS != 0 { v &= !u::RFCOMM_V24_RTR; }
    v
}

/// The bits a `TIOCMGET` reports: the peer's inputs, plus this end's own signal
/// byte masked to the two output bits.
///
/// The local half is a raw mask of the V.24 byte, NOT a translation of it, so
/// the two bit sets line up only by coincidence of their numbering: the ready-
/// to-communicate signal reads back as request-to-send, and the flow bit reads
/// back as data-terminal-ready. Translating instead would report different bits
/// than every existing reader of this interface expects.
/// # C: O(1)
pub fn tiocmget(local_v24: u8, remote_tiocm: u32) -> u32 {
    (local_v24 as u32 & (TIOCM_DTR | TIOCM_RTS)) | remote_tiocm
}
