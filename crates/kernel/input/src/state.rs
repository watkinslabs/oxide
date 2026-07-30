use alloc::vec::Vec;

use crate::registry::VirtioInputDev;
use crate::uapi::{
    ABS_CNT, EV_ABS, EV_CNT, EV_FF, EV_KEY, EV_LED, EV_MSC, EV_PWR, EV_REL, EV_REP,
    EV_SND, EV_SW, EV_SYN, FF_CNT, KEY_CNT, KEY_RELEASED, KEY_REPEAT, LED_CNT, MSC_CNT,
    REL_CNT, REP_DELAY, REP_PERIOD, SND_CNT, SW_CNT, SYN_CONFIG, SYN_MT_REPORT, SYN_REPORT,
};

const fn bytes_for(bits: usize) -> usize { (bits + 7) / 8 }

const EV_BYTES: usize = bytes_for(EV_CNT);
const KEY_BYTES: usize = bytes_for(KEY_CNT);
const REL_BYTES: usize = bytes_for(REL_CNT);
const ABS_BYTES: usize = bytes_for(ABS_CNT);
const MSC_BYTES: usize = bytes_for(MSC_CNT);
const SW_BYTES: usize = bytes_for(SW_CNT);
const LED_BYTES: usize = bytes_for(LED_CNT);
const SND_BYTES: usize = bytes_for(SND_CNT);
const FF_BYTES: usize = bytes_for(FF_CNT);

pub(crate) struct AcceptedEvent {
    pub(crate) value: i32,
    pub(crate) slot: Option<i32>,
}

impl AcceptedEvent {
    fn plain(value: i32) -> Self { Self { value, slot: None } }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputEvent {
    pub ev_type: u16,
    pub code: u16,
    pub value: i32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OutputBatch {
    pub events: Vec<OutputEvent>,
}

fn bit_is_set(bits: &[u8], bit: usize) -> bool {
    bits.get(bit / 8).is_some_and(|byte| byte & (1u8 << (bit % 8)) != 0)
}

fn set_bit(bits: &mut [u8], bit: usize, value: bool) {
    if let Some(byte) = bits.get_mut(bit / 8) {
        let mask = 1u8 << (bit % 8);
        if value { *byte |= mask; } else { *byte &= !mask; }
    }
}

fn supported(bits: &[u8], code: u16) -> bool {
    bit_is_set(bits, code as usize)
}

impl VirtioInputDev {
    /// # C: O(1)
    pub(crate) fn accept_event(
        &mut self,
        ev_type: u16,
        code: u16,
        value: i32,
    ) -> Option<AcceptedEvent> {
        if self.inhibited || !bit_is_set(&self.ev_bits, ev_type as usize) {
            return None;
        }
        match ev_type {
            EV_SYN if matches!(code, SYN_REPORT | SYN_CONFIG | SYN_MT_REPORT) => {
                Some(AcceptedEvent::plain(value))
            }
            EV_KEY if supported(&self.key_bits.bits[..KEY_BYTES], code) => {
                if value == KEY_REPEAT { return Some(AcceptedEvent::plain(value)); }
                let active = bit_is_set(&self.key_state.bits, code as usize);
                let next = value != KEY_RELEASED;
                if active == next { return None; }
                set_bit(&mut self.key_state.bits, code as usize, next);
                Some(AcceptedEvent::plain(value))
            }
            EV_REL if supported(&self.rel_bits.bits[..REL_BYTES], code) && value != 0 => {
                Some(AcceptedEvent::plain(value))
            }
            EV_ABS if supported(&self.abs_bits.bits[..ABS_BYTES], code) => {
                self.accept_absolute(code, value)
                    .map(|event| AcceptedEvent { value: event.value, slot: event.slot })
            }
            EV_MSC if supported(&self.msc_bits.bits[..MSC_BYTES], code) => {
                Some(AcceptedEvent::plain(value))
            }
            EV_SW if supported(&self.sw_bits.bits[..SW_BYTES], code) => {
                let active = bit_is_set(&self.switch_state.bits, code as usize);
                let next = value != 0;
                if active == next { return None; }
                set_bit(&mut self.switch_state.bits, code as usize, next);
                Some(AcceptedEvent::plain(value))
            }
            EV_LED if supported(&self.led_bits.bits[..LED_BYTES], code) => {
                let active = bit_is_set(&self.led_state.bits, code as usize);
                let next = value != 0;
                if active == next { return None; }
                set_bit(&mut self.led_state.bits, code as usize, next);
                Some(AcceptedEvent::plain(value))
            }
            EV_SND if supported(&self.snd_bits.bits[..SND_BYTES], code) => {
                set_bit(&mut self.sound_state.bits, code as usize, value != 0);
                Some(AcceptedEvent::plain(value))
            }
            EV_REP if code < self.repeat.len() as u16 && value >= 0 => {
                let slot = &mut self.repeat[code as usize];
                if *slot == value as u32 { return None; }
                *slot = value as u32;
                Some(AcceptedEvent::plain(value))
            }
            EV_FF if value >= 0 => Some(AcceptedEvent::plain(value)),
            EV_PWR => Some(AcceptedEvent::plain(value)),
            _ => None,
        }
    }

    /// # C: O(KEY_CNT)
    pub(crate) fn take_pressed_keys(&mut self) -> Vec<u16> {
        let mut keys = Vec::new();
        for code in 0..KEY_BYTES * 8 {
            if bit_is_set(&self.key_state.bits, code) {
                keys.push(code as u16);
            }
        }
        self.key_state.bits[..KEY_BYTES].fill(0);
        keys
    }

    /// # C: O(1)
    pub(crate) fn apply_output_event(&mut self, event: &OutputEvent) -> Option<OutputEvent> {
        if !matches!(event.ev_type, EV_LED | EV_SND | EV_REP) {
            return None;
        }
        let accepted = self.accept_event(event.ev_type, event.code, event.value)?;
        Some(OutputEvent {
            ev_type: event.ev_type,
            code: event.code,
            value: accepted.value,
        })
    }

    /// # C: O(LED_CNT + SND_CNT)
    pub(crate) fn inhibit_output_batch(&self) -> OutputBatch {
        let mut batch = OutputBatch::default();
        append_output_state(
            &mut batch, EV_LED, &self.led_bits.bits[..LED_BYTES],
            &self.led_state.bits[..LED_BYTES], false,
        );
        append_output_state(
            &mut batch, EV_SND, &self.snd_bits.bits[..SND_BYTES],
            &self.sound_state.bits[..SND_BYTES], false,
        );
        batch
    }

    /// # C: O(LED_CNT + SND_CNT)
    pub(crate) fn uninhibit_output_batch(&self) -> OutputBatch {
        let mut batch = OutputBatch::default();
        append_output_state(
            &mut batch, EV_LED, &self.led_bits.bits[..LED_BYTES],
            &self.led_state.bits[..LED_BYTES], true,
        );
        append_output_state(
            &mut batch, EV_SND, &self.snd_bits.bits[..SND_BYTES],
            &self.sound_state.bits[..SND_BYTES], true,
        );
        if bit_is_set(&self.ev_bits, EV_REP as usize) {
            batch.events.push(OutputEvent {
                ev_type: EV_REP,
                code: REP_PERIOD,
                value: self.repeat[REP_PERIOD as usize] as i32,
            });
            batch.events.push(OutputEvent {
                ev_type: EV_REP,
                code: REP_DELAY,
                value: self.repeat[REP_DELAY as usize] as i32,
            });
        }
        batch
    }

    /// Seed pre-registration Linux input state into the canonical model.
    /// # C: O(state bytes)
    pub fn seed_state_bits(&mut self, ev_type: u16, bits: &[u8]) -> bool {
        let dst = match ev_type {
            EV_KEY => &mut self.key_state.bits[..KEY_BYTES],
            EV_SW => &mut self.switch_state.bits[..SW_BYTES],
            EV_LED => &mut self.led_state.bits[..LED_BYTES],
            EV_SND => &mut self.sound_state.bits[..SND_BYTES],
            _ => return false,
        };
        dst.fill(0);
        let len = dst.len().min(bits.len());
        dst[..len].copy_from_slice(&bits[..len]);
        true
    }

    /// Canonical dynamic bitmap with Linux event-type width.
    /// # C: O(1)
    pub fn state_bits(&self, ev_type: u16) -> Option<&[u8]> {
        match ev_type {
            EV_KEY => Some(&self.key_state.bits[..KEY_BYTES]),
            EV_SW => Some(&self.switch_state.bits[..SW_BYTES]),
            EV_LED => Some(&self.led_state.bits[..LED_BYTES]),
            EV_SND => Some(&self.sound_state.bits[..SND_BYTES]),
            _ => None,
        }
    }

    /// Canonical capability bitmap with Linux event-type width.
    /// # C: O(1)
    pub fn capability_bits(&self, ev_type: u16) -> Option<&[u8]> {
        match ev_type {
            EV_SYN => Some(&self.ev_bits[..EV_BYTES]),
            EV_KEY => Some(&self.key_bits.bits[..KEY_BYTES]),
            EV_REL => Some(&self.rel_bits.bits[..REL_BYTES]),
            EV_ABS => Some(&self.abs_bits.bits[..ABS_BYTES]),
            EV_MSC => Some(&self.msc_bits.bits[..MSC_BYTES]),
            EV_SW => Some(&self.sw_bits.bits[..SW_BYTES]),
            EV_LED => Some(&self.led_bits.bits[..LED_BYTES]),
            EV_SND => Some(&self.snd_bits.bits[..SND_BYTES]),
            EV_FF => Some(&self.ff_bits.bits[..FF_BYTES]),
            _ => None,
        }
    }
}

fn append_output_state(
    batch: &mut OutputBatch,
    ev_type: u16,
    capabilities: &[u8],
    state: &[u8],
    activate: bool,
) {
    for code in 0..capabilities.len() * 8 {
        if !bit_is_set(capabilities, code) { continue; }
        let active = bit_is_set(state, code);
        batch.events.push(OutputEvent {
            ev_type,
            code: code as u16,
            value: i32::from(activate && active),
        });
    }
}

/// Run one state operation while the exact input object's canonical lock is held.
/// # C: O(N_devices + callback)
pub fn with_state_bits_by_identity<R>(
    device_key: virtio::VirtioChildDeviceKey,
    input_id: u32,
    evdev_id: u32,
    ev_type: u16,
    callback: impl FnOnce(&[u8]) -> R,
) -> Option<R> {
    let devices = crate::registry::DEVICES.lock();
    let dev = devices.iter().find(|dev| {
        dev.device_key == device_key && dev.input_id == input_id && dev.evdev_id == evdev_id
    })?;
    Some(callback(dev.state_bits(ev_type)?))
}
