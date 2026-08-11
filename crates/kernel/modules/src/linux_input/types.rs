use crate::linux_device::types::LinuxDevice;
use core::ffi::{c_char, c_void};
pub(super) use input::{
    ABS_CNT, EV_ABS, EV_CNT, EV_FF, EV_KEY, EV_LED, EV_MSC, EV_PWR, EV_REL, EV_SND,
    EV_SW, EV_SYN, FF_CNT, INPUT_PROP_CNT, KEY_CNT, LED_CNT, MSC_CNT, REL_CNT,
    SND_CNT, SW_CNT, SYN_REPORT,
};

pub(super) const LINUX_OK: i32 = 0;
pub(super) const LINUX_EINVAL: i32 = 22;
pub(super) const LINUX_EBUSY: i32 = 16;
pub(super) const LINUX_ENOMEM: i32 = 12;
pub(super) const LINUX_ENOSPC: i32 = 28;

pub(super) const BITS_PER_LONG: usize = core::mem::size_of::<usize>() * 8;
pub(super) const INPUT_EV_WORDS: usize = words_for(EV_CNT);
pub(super) const INPUT_KEY_WORDS: usize = words_for(KEY_CNT);
pub(super) const INPUT_REL_WORDS: usize = words_for(REL_CNT);
pub(super) const INPUT_ABS_WORDS: usize = words_for(ABS_CNT);
pub(super) const INPUT_MSC_WORDS: usize = words_for(MSC_CNT);
pub(super) const INPUT_SW_WORDS: usize = words_for(SW_CNT);
pub(super) const INPUT_LED_WORDS: usize = words_for(LED_CNT);
pub(super) const INPUT_SND_WORDS: usize = words_for(SND_CNT);
pub(super) const INPUT_FF_WORDS: usize = words_for(FF_CNT);
pub(super) const INPUT_PROP_WORDS: usize = words_for(INPUT_PROP_CNT);
pub(super) const SYNTHETIC_DEVICE_KEY_BASE: u32 = 1u32 << 31;
pub(super) const SYNTHETIC_DEVICE_KEY_MASK: u32 = !SYNTHETIC_DEVICE_KEY_BASE;
#[cfg(test)]
pub(super) const INPUT_EVENT_BYTES: usize = 24;

pub(super) const fn words_for(bits: usize) -> usize {
    (bits + BITS_PER_LONG - 1) / BITS_PER_LONG
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct LinuxInputId {
    pub(super) bustype: u16,
    pub(super) vendor: u16,
    pub(super) product: u16,
    pub(super) version: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct LinuxInputAbsInfo {
    pub(super) value: i32,
    pub(super) minimum: i32,
    pub(super) maximum: i32,
    pub(super) fuzz: i32,
    pub(super) flat: i32,
    pub(super) resolution: i32,
}

#[cfg(test)]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct LinuxInputEvent {
    pub(super) tv_sec: i64,
    pub(super) tv_usec: i64,
    pub(super) ev_type: u16,
    pub(super) code: u16,
    pub(super) value: i32,
}

#[repr(C)]
pub(super) struct LinuxInputDev {
    pub(super) name: *const c_char,
    pub(super) phys: *const c_char,
    pub(super) uniq: *const c_char,
    pub(super) id: LinuxInputId,
    pub(super) propbit: [usize; INPUT_PROP_WORDS],
    pub(super) evbit: [usize; INPUT_EV_WORDS],
    pub(super) keybit: [usize; INPUT_KEY_WORDS],
    pub(super) relbit: [usize; INPUT_REL_WORDS],
    pub(super) absbit: [usize; INPUT_ABS_WORDS],
    pub(super) mscbit: [usize; INPUT_MSC_WORDS],
    pub(super) ledbit: [usize; INPUT_LED_WORDS],
    pub(super) sndbit: [usize; INPUT_SND_WORDS],
    pub(super) ffbit: [usize; INPUT_FF_WORDS],
    pub(super) swbit: [usize; INPUT_SW_WORDS],
    pub(super) hint_events_per_packet: u32,
    pub(super) keycodemax: u32,
    pub(super) keycodesize: u32,
    _pad_keycode: u32,
    pub(super) keycode: *mut c_void,
    pub(super) setkeycode: *mut c_void,
    pub(super) getkeycode: *mut c_void,
    pub(super) ff: *mut c_void,
    pub(super) poller: *mut c_void,
    pub(super) repeat_key: u32,
    _pad_repeat: u32,
    _timer: [u8; 40],
    pub(super) rep: *mut c_void,
    pub(super) mt: *mut c_void,
    pub(super) absinfo: *mut LinuxInputAbsInfo,
    pub(super) key: [usize; INPUT_KEY_WORDS],
    pub(super) led: [usize; INPUT_LED_WORDS],
    pub(super) snd: [usize; INPUT_SND_WORDS],
    pub(super) sw: [usize; INPUT_SW_WORDS],
    pub(super) open: *mut c_void,
    pub(super) close: *mut c_void,
    pub(super) flush: *mut c_void,
    pub(super) event: *mut c_void,
    pub(super) grab: *mut c_void,
    _event_lock: [u8; 8],
    _mutex: [u8; 32],
    _users: u32,
    _going_away: u8,
    _pad_going_away: [u8; 3],
    pub(super) dev: LinuxDevice,
    _h_list: [*mut c_void; 2],
    _node: [*mut c_void; 2],
    _num_vals: u32,
    _max_vals: u32,
    _vals: *mut c_void,
    _devres_managed: u8,
    _pad_devres: [u8; 7],
    _timestamp: [i64; 3],
    _inhibited: u8,
    _pad_inhibited: [u8; 7],
}
