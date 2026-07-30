use alloc::vec::Vec;

use crate::registry::VirtioInputDev;
use crate::state::AcceptedEvent;
use crate::uapi::{
    ABS_MT_SLOT, EV_ABS, EV_KEY, EV_SYN, SYN_REPORT, SYNTHETIC_SYNC_VALUE,
};

const MAX_PACKET_VALUES: usize = 1024;
const PACKET_TAIL_VALUES: usize = 2;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InputValue {
    pub ev_type: u16,
    pub code: u16,
    pub value: i32,
}

impl InputValue {
    pub(crate) const fn new(ev_type: u16, code: u16, value: i32) -> Self {
        Self { ev_type, code, value }
    }
}

impl VirtioInputDev {
    fn stage_value(&mut self, ev_type: u16, code: u16, value: i32) {
        self.pending_values.push(InputValue::new(ev_type, code, value));
    }

    fn take_report(&mut self) -> Option<Vec<InputValue>> {
        (!self.pending_values.is_empty())
            .then(|| core::mem::take(&mut self.pending_values))
    }

    /// # C: O(1) amortized
    pub(crate) fn stage_accepted(
        &mut self,
        ev_type: u16,
        code: u16,
        accepted: AcceptedEvent,
    ) -> Option<Vec<InputValue>> {
        if let Some(slot) = accepted.slot {
            self.stage_value(EV_ABS, ABS_MT_SLOT, slot);
        }
        self.stage_value(ev_type, code, accepted.value);
        if ev_type == EV_SYN && code == SYN_REPORT {
            return self.take_report();
        }
        if self.pending_values.len() >= MAX_PACKET_VALUES - PACKET_TAIL_VALUES {
            self.stage_value(EV_SYN, SYN_REPORT, SYNTHETIC_SYNC_VALUE);
            return self.take_report();
        }
        None
    }

    /// # C: O(KEY_CNT)
    pub(crate) fn release_keys_to_pending(&mut self) -> bool {
        let keys = self.take_pressed_keys();
        for code in keys.iter().copied() {
            self.stage_value(EV_KEY, code, 0);
        }
        !keys.is_empty()
    }

    /// # C: O(MT slots)
    pub(crate) fn release_mt_to_pending(&mut self) -> bool {
        let values = self.release_mt_values();
        let released = !values.is_empty();
        self.pending_values.extend(values);
        released
    }

    /// # C: O(1) amortized
    pub(crate) fn flush_synthetic_report(&mut self) -> Option<Vec<InputValue>> {
        self.stage_value(EV_SYN, SYN_REPORT, SYNTHETIC_SYNC_VALUE);
        self.take_report()
    }
}
