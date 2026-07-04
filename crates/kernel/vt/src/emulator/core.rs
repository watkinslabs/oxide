use crate::vc::Vc;

use super::{CsiState, Emulator};

impl Emulator {
    /// New emulator in the ground state.
    /// # C: O(1).
    pub fn new() -> Self {
        Emulator::default()
    }

    /// Current parser superstate (test/debug).
    /// # C: O(1).
    pub fn state(&self) -> CsiState {
        self.state
    }

    /// Feed a slice of bytes through the emulator, mutating `vc`.
    /// # C: O(n) plus O(cols*rows) per scroll/erase byte.
    pub fn feed_bytes(&mut self, vc: &mut Vc, bytes: &[u8]) {
        for &b in bytes {
            self.feed(vc, b);
        }
    }

    /// Feed one byte through the state machine, mutating `vc`.
    /// # C: O(1) amortized; O(cols*rows) on a scroll/erase byte.
    pub fn feed(&mut self, vc: &mut Vc, byte: u8) {
        vc.mark_cursor_dirty();
        if (byte == 0x18 || byte == 0x1a) && self.state != CsiState::Ground {
            self.state = CsiState::Ground;
            return;
        }
        match self.state {
            CsiState::Ground => self.ground(vc, byte),
            CsiState::Esc => self.esc(vc, byte),
            CsiState::CsiParam => self.csi_param(vc, byte),
            CsiState::CsiInter => self.csi_inter(vc, byte),
            CsiState::Charset => self.charset_designate(vc, byte),
            CsiState::Hash => self.hash(vc, byte),
            CsiState::Osc => {
                self.osc_len = 0;
                self.state = CsiState::OscString;
                self.osc_string(vc, byte);
            }
            CsiState::OscString => self.osc_string(vc, byte),
            CsiState::DcsString => self.dcs_string(byte),
        }
    }
}
