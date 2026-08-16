//! The settings word. Two of them describe a controller: what it is capable of,
//! which never changes while it is present, and what is switched on right now.
//! A bit may only be current if it is also supported, and every `SET_*` answers
//! with the whole current word rather than the bit it touched — a client is
//! expected to re-read all of it, because one setting can turn another off.

use alloc::vec::Vec;

use super::codec::Writer;
use crate::uapi::mgmt::flags::*;
use crate::uapi::mgmt::op::*;

/// A controller's supported and current settings.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Settings {
    pub supported: u32,
    pub current: u32,
}

impl Settings {
    /// # C: O(1)
    pub fn new(supported: u32, current: u32) -> Settings {
        Settings { supported, current: current & supported }
    }

    /// Whether the setting is on. # C: O(1)
    pub fn has(&self, bit: u32) -> bool { self.current & bit != 0 }

    /// Whether the controller can do it at all. # C: O(1)
    pub fn supports(&self, bit: u32) -> bool { self.supported & bit != 0 }

    /// Turn a setting on, but only if it is supported: an unsupported bit
    /// cannot become current, which is what keeps the two words consistent. # C: O(1)
    pub fn set(&mut self, bit: u32, on: bool) {
        if on { self.current |= bit & self.supported; } else { self.current &= !bit; }
    }

    /// The word every `SET_*` answers with. # C: O(1)
    pub fn current_word(&self) -> u32 { self.current }

    /// The current word as a `SET_*` response payload. # C: O(1)
    pub fn encode_current(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(4);
        w.u32(self.current);
        w.finish()
    }
}

/// Which setting bit a mode command switches, for the commands that switch
/// exactly one. A command not in this list either takes parameters beyond the
/// mode byte or changes no single bit. # C: O(1)
pub fn setting_for_opcode(opcode: u16) -> Option<u32> {
    let bit = match opcode {
        MGMT_OP_SET_POWERED => MGMT_SETTING_POWERED,
        MGMT_OP_SET_DISCOVERABLE => MGMT_SETTING_DISCOVERABLE,
        MGMT_OP_SET_CONNECTABLE => MGMT_SETTING_CONNECTABLE,
        MGMT_OP_SET_FAST_CONNECTABLE => MGMT_SETTING_FAST_CONNECTABLE,
        MGMT_OP_SET_BONDABLE => MGMT_SETTING_BONDABLE,
        MGMT_OP_SET_LINK_SECURITY => MGMT_SETTING_LINK_SECURITY,
        MGMT_OP_SET_SSP => MGMT_SETTING_SSP,
        MGMT_OP_SET_HS => MGMT_SETTING_HS,
        MGMT_OP_SET_LE => MGMT_SETTING_LE,
        MGMT_OP_SET_ADVERTISING => MGMT_SETTING_ADVERTISING,
        MGMT_OP_SET_BREDR => MGMT_SETTING_BREDR,
        MGMT_OP_SET_SECURE_CONN => MGMT_SETTING_SECURE_CONN,
        MGMT_OP_SET_DEBUG_KEYS => MGMT_SETTING_DEBUG_KEYS,
        MGMT_OP_SET_PRIVACY => MGMT_SETTING_PRIVACY,
        MGMT_OP_SET_WIDEBAND_SPEECH => MGMT_SETTING_WIDEBAND_SPEECH,
        _ => return None,
    };
    Some(bit)
}

#[cfg(test)]
#[path = "tests/settings.rs"]
mod tests;
