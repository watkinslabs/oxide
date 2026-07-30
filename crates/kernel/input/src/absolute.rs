use alloc::vec::Vec;

use crate::{packet::InputValue, registry::VirtioInputDev, types::VirtioInputAbsInfo};
use crate::uapi::{
    ABS_CNT, ABS_MT_FIRST, ABS_MT_LAST, ABS_MT_SLOT, ABS_MT_TRACKING_ID, EV_ABS,
};

const MT_VALUE_COUNT: usize = (ABS_MT_LAST - ABS_MT_FIRST + 1) as usize;
const MAX_MT_SLOTS: usize = 1024;
const TRACKING_INACTIVE: i32 = -1;

#[derive(Clone)]
pub(crate) struct MtState {
    selected: usize,
    slots: Vec<[i32; MT_VALUE_COUNT]>,
}

impl MtState {
    fn new(count: usize, selected: usize) -> Self {
        let mut slots = alloc::vec![[0; MT_VALUE_COUNT]; count];
        let tracking = (ABS_MT_TRACKING_ID - ABS_MT_FIRST) as usize;
        for slot in slots.iter_mut() {
            slot[tracking] = TRACKING_INACTIVE;
        }
        Self { selected, slots }
    }
}

#[derive(Copy, Clone)]
pub(crate) struct AbsoluteEvent {
    pub value: i32,
    pub slot: Option<i32>,
}

fn defuzz(value: i32, old: i32, fuzz: i32) -> i32 {
    let fuzz = i64::from(fuzz);
    if fuzz <= 0 { return value; }
    let value64 = i64::from(value);
    let old64 = i64::from(old);
    if value64 > old64 - fuzz / 2 && value64 < old64 + fuzz / 2 {
        return old;
    }
    if value64 > old64 - fuzz && value64 < old64 + fuzz {
        return ((old64 * 3 + value64) / 4) as i32;
    }
    if value64 > old64 - fuzz * 2 && value64 < old64 + fuzz * 2 {
        return ((old64 + value64) / 2) as i32;
    }
    value
}

fn is_mt_value(code: u16) -> bool {
    (ABS_MT_FIRST..=ABS_MT_LAST).contains(&code)
}

impl VirtioInputDev {
    /// # C: O(MT slots)
    pub(crate) fn configure_absolute(&mut self) {
        self.mt_state = None;
        let slot = ABS_MT_SLOT as usize;
        if !self.abs_code_supported(ABS_MT_SLOT) { return; }
        let Some(info) = self.abs_info[slot] else { return; };
        let min = info.min as i32;
        let max = info.max as i32;
        if min != 0 || max < 0 { return; }
        let count = max as usize + 1;
        if count == 0 || count > MAX_MT_SLOTS { return; }
        let selected = usize::try_from(self.abs_values[slot])
            .ok()
            .filter(|selected| *selected < count)
            .unwrap_or(0);
        self.abs_values[slot] = selected as i32;
        self.mt_state = Some(MtState::new(count, selected));
    }

    /// # C: O(1)
    pub(crate) fn abs_code_supported(&self, code: u16) -> bool {
        let code = code as usize;
        code < ABS_CNT
            && self.abs_bits.bits[code / 8] & (1u8 << (code % 8)) != 0
    }

    /// Seed one pre-registration absolute-axis value.
    /// # C: O(1)
    pub fn seed_abs_value(&mut self, code: u16, value: i32) -> bool {
        let Some(slot) = self.abs_values.get_mut(code as usize) else { return false; };
        *slot = value;
        true
    }

    /// # C: O(1)
    pub(crate) fn accept_absolute(&mut self, code: u16, value: i32) -> Option<AbsoluteEvent> {
        if !self.abs_code_supported(code) { return None; }
        if code == ABS_MT_SLOT {
            let mt = self.mt_state.as_mut()?;
            let slot = usize::try_from(value).ok()?;
            if slot >= mt.slots.len() { return None; }
            mt.selected = slot;
            return None;
        }

        let fuzz = self.abs_info[code as usize]
            .map(|info| info.fuzz as i32)
            .unwrap_or(0);
        if is_mt_value(code) {
            let Some(mt) = self.mt_state.as_mut() else {
                return Some(AbsoluteEvent { value, slot: None });
            };
            let index = (code - ABS_MT_FIRST) as usize;
            let old = mt.slots[mt.selected][index];
            let value = defuzz(value, old, fuzz);
            if value == old { return None; }
            mt.slots[mt.selected][index] = value;
            let selected = mt.selected as i32;
            let slot = if self.abs_values[ABS_MT_SLOT as usize] != selected {
                self.abs_values[ABS_MT_SLOT as usize] = selected;
                Some(selected)
            } else {
                None
            };
            return Some(AbsoluteEvent { value, slot });
        }

        let old = self.abs_values[code as usize];
        let value = defuzz(value, old, fuzz);
        if value == old { return None; }
        self.abs_values[code as usize] = value;
        Some(AbsoluteEvent { value, slot: None })
    }

    /// # C: O(MT slots)
    pub(crate) fn release_mt_values(&mut self) -> Vec<InputValue> {
        let Some(mt) = self.mt_state.as_mut() else { return Vec::new(); };
        let tracking = (ABS_MT_TRACKING_ID - ABS_MT_FIRST) as usize;
        let mut values = Vec::new();
        for slot in 0..mt.slots.len() {
            if mt.slots[slot][tracking] < 0 { continue; }
            if self.abs_values[ABS_MT_SLOT as usize] != slot as i32 {
                self.abs_values[ABS_MT_SLOT as usize] = slot as i32;
                values.push(InputValue::new(EV_ABS, ABS_MT_SLOT, slot as i32));
            }
            mt.slots[slot][tracking] = TRACKING_INACTIVE;
            values.push(InputValue::new(
                EV_ABS, ABS_MT_TRACKING_ID, TRACKING_INACTIVE,
            ));
        }
        values
    }

    /// Current absolute-axis value for an advertised code.
    /// # C: O(1)
    pub fn abs_value(&self, code: u16) -> Option<i32> {
        self.abs_code_supported(code).then(|| self.abs_values[code as usize])
    }

    /// Static absolute-axis parameters for an advertised code.
    /// # C: O(1)
    pub fn abs_parameters(&self, code: u16) -> Option<VirtioInputAbsInfo> {
        self.abs_code_supported(code)
            .then(|| self.abs_info[code as usize])
            .flatten()
    }
}
