//! Pairing-method selection.
//!
//! The tables are indexed by the peer's capability first and the local one
//! second, which is not symmetric: reading them the other way round produces a
//! plausible method that disagrees with the peer's choice, and the two sides
//! then compute different confirm values. The overrides on top of the tables
//! matter as much as the tables themselves — most of them exist to avoid
//! prompting a user who cannot answer, and one of them is the only thing that
//! keeps two keyboard-display devices from both trying to enter a passkey.

use crate::uapi::bt::{BT_SECURITY_FIPS, BT_SECURITY_MEDIUM};
use crate::uapi::smp::{
    SMP_AUTH_MITM, SMP_IO_COUNT, SMP_IO_KEYBOARD_DISPLAY, SMP_IO_NO_INPUT_OUTPUT,
};

/// No user interaction; the temporary key is zero.
pub const JUST_WORKS: u8 = 0x00;
/// Ask the user to confirm, with no number to compare.
pub const JUST_CFM: u8 = 0x01;
/// Ask the user to type the passkey the peer displays.
pub const REQ_PASSKEY: u8 = 0x02;
/// Show a locally generated passkey and have the user confirm it.
pub const CFM_PASSKEY: u8 = 0x03;
/// Use out-of-band data.
pub const REQ_OOB: u8 = 0x04;
/// Show a locally generated passkey for the user to type on the peer.
pub const DSP_PASSKEY: u8 = 0x05;
/// Both sides could do either; the role decides which. Never a final answer.
pub const OVERLAP: u8 = 0xff;

/// Legacy pairing methods, indexed by peer capability then local capability.
pub static LEGACY_METHOD: [[u8; SMP_IO_COUNT]; SMP_IO_COUNT] = [
    [JUST_WORKS,  JUST_CFM,    REQ_PASSKEY, JUST_WORKS, REQ_PASSKEY],
    [JUST_WORKS,  JUST_CFM,    REQ_PASSKEY, JUST_WORKS, REQ_PASSKEY],
    [CFM_PASSKEY, CFM_PASSKEY, REQ_PASSKEY, JUST_WORKS, CFM_PASSKEY],
    [JUST_WORKS,  JUST_CFM,    JUST_WORKS,  JUST_WORKS, JUST_CFM   ],
    [CFM_PASSKEY, CFM_PASSKEY, REQ_PASSKEY, JUST_WORKS, OVERLAP    ],
];

/// Secure-connections methods, indexed the same way. It differs from the
/// legacy table in that a passkey can be displayed rather than confirmed, and
/// two display-yes-no devices compare a number instead of just confirming.
pub static SC_METHOD: [[u8; SMP_IO_COUNT]; SMP_IO_COUNT] = [
    [JUST_WORKS,  JUST_CFM,    REQ_PASSKEY, JUST_WORKS, REQ_PASSKEY],
    [JUST_WORKS,  CFM_PASSKEY, REQ_PASSKEY, JUST_WORKS, CFM_PASSKEY],
    [DSP_PASSKEY, DSP_PASSKEY, REQ_PASSKEY, JUST_WORKS, DSP_PASSKEY],
    [JUST_WORKS,  JUST_CFM,    JUST_WORKS,  JUST_WORKS, JUST_CFM   ],
    [DSP_PASSKEY, CFM_PASSKEY, REQ_PASSKEY, JUST_WORKS, CFM_PASSKEY],
];

/// The table entry for a capability pair. A capability outside the defined
/// range is not an error: it degrades to a plain confirmation, which a later
/// override may turn into no interaction at all. # C: O(1)
pub fn table_method(sc: bool, local_io: u8, remote_io: u8) -> u8 {
    if local_io > SMP_IO_KEYBOARD_DISPLAY || remote_io > SMP_IO_KEYBOARD_DISPLAY {
        return JUST_CFM;
    }
    let table = if sc { &SC_METHOD } else { &LEGACY_METHOD };
    table[remote_io as usize][local_io as usize]
}

/// The legacy method for an exchange.
///
/// `auth` is the requirement the two pairing PDUs agreed on. Without a
/// man-in-the-middle requirement the table is not consulted at all, because
/// no legacy method resists one and pretending otherwise would let a caller
/// believe an unauthenticated key is authenticated. # C: O(1)
pub fn legacy_method(auth: u8, local_io: u8, remote_io: u8, initiator: bool) -> u8 {
    let mut m = if auth & SMP_AUTH_MITM == 0 {
        JUST_CFM
    } else {
        table_method(false, local_io, remote_io)
    };
    // A locally initiated attempt needs no confirmation: the user already
    // asked for it.
    if m == JUST_CFM && initiator { m = JUST_WORKS; }
    // Nothing to confirm with when there is no way to ask.
    if m == JUST_CFM && local_io == SMP_IO_NO_INPUT_OUTPUT { m = JUST_WORKS; }
    // Two keyboard-displays: the initiator shows and confirms, the responder
    // types. Both doing the same thing would deadlock the exchange.
    if m == OVERLAP { m = if initiator { CFM_PASSKEY } else { REQ_PASSKEY }; }
    m
}

/// The secure-connections method for an exchange.
///
/// Out-of-band data on either side wins outright — it authenticates the
/// exchange without the user. Otherwise a requirement from either side is
/// enough to consult the table. # C: O(1)
pub fn sc_method(
    local_io: u8,
    remote_io: u8,
    local_auth: u8,
    remote_auth: u8,
    local_oob: bool,
    remote_oob: bool,
    initiator: bool,
) -> u8 {
    if local_oob || remote_oob { return REQ_OOB; }
    let mitm = (local_auth & SMP_AUTH_MITM != 0) || (remote_auth & SMP_AUTH_MITM != 0);
    let mut m = if mitm { table_method(true, local_io, remote_io) } else { JUST_WORKS };
    if m == JUST_CFM && initiator { m = JUST_WORKS; }
    m
}

/// Whether a method authenticates the exchange against a relay. Only this
/// distinction decides whether the resulting key may be called authenticated.
/// # C: O(1)
pub fn method_is_authenticated(method: u8) -> bool {
    method != JUST_WORKS && method != JUST_CFM
}

/// The level a completed pairing by this method reaches. # C: O(1)
pub fn method_sec_level(method: u8) -> u8 {
    if method_is_authenticated(method) { BT_SECURITY_FIPS } else { BT_SECURITY_MEDIUM }
}
